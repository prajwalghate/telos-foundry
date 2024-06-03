// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
pragma experimental ABIEncoderV2;

import "@openzeppelin/access/Ownable.sol";
import "@openzeppelin/utils/math/SafeMath.sol";
import "@openzeppelin/security/ReentrancyGuard.sol";
import "@openzeppelin/token/ERC20/ERC20.sol";
import "@openzeppelin/token/ERC20/utils/SafeERC20.sol";

contract MasterchefV2 is Ownable, ReentrancyGuard {
    using SafeMath for uint256;
    using SafeERC20 for IERC20;

    // MasterChefRivera update: it pays rewards not only in SLUSH, but also in an EXTRA token.

    /// @notice Info of each MCV2 user.
    /// `amount` LP token amount the user has provided.
    /// `rewardDebt` Used to calculate the correct amount of rewards. See explanation below.
    ///
    /// We do some fancy math here. Basically, any point in time, the amount of SLUSH
    /// entitled to a user but is pending to be distributed is:
    ///
    ///   pending reward = (user share * pool.accSlushPerShare) - user.rewardDebt
    ///
    ///   Whenever a user deposits or withdraws LP tokens to a pool. Here's what happens:
    ///   1. The pool's `accSlushPerShare` (and `lastRewardBlock`) gets updated.
    ///   2. User receives the pending reward sent to his/her address.
    ///   3. User's `amount` gets updated. Pool's `totalBoostedShare` gets updated.
    ///   4. User's `rewardDebt` and `extraRewardDebt` get updated.
    struct UserInfo {
        uint256 amount;
        uint256 rewardDebt;
        uint256 extraRewardDebt;
        uint256 boostMultiplier;
    }

    /// @notice Info of each MCV2 pool.
    /// `allocPoint` The amount of allocation points assigned to the pool.
    ///     Also known as the amount of "multipliers". Combined with `totalXAllocPoint`, it defines the % of
    ///     SLUSH (& EXTRA) rewards each pool gets.
    /// `accSlushPerShare` Accumulated SLUSH per share, times 1e12.
    /// `accExtraPerShare` Accumulated EXTRA token per share, times 1e12.
    /// `lastRewardBlock` Last block number that pool update action is executed.
    /// `isRegular` The flag to set pool is regular or special. See below:
    ///     In MasterChef V2 farms are "regular pools". "special pools", which use a different sets of
    ///     `allocPoint` and their own `totalSpecialAllocPoint` are designed to handle the distribution of
    ///     the SLUSH rewards to all the  products.
    /// `totalBoostedShare` The total amount of user shares in each pool. After considering the share boosts.
    struct PoolInfo {
        uint256 accSlushPerShare;
        uint256 accExtraPerShare;
        uint256 lastRewardBlock;
        uint256 allocPoint;
        uint256 totalBoostedShare;
        bool isRegular;
    }

    /// @notice Address of SLUSH token.
    IERC20 public immutable SLUSH;
    /// @notice Address of EXTRA token.
    IERC20 public immutable EXTRA;

    /// @notice The contract handles the share boosts.
    address public boostContract;

    /// @notice Info of each MCV2 pool.
    PoolInfo[] public poolInfo;
    /// @notice Address of the LP token for each MCV2 pool.
    IERC20[] public lpToken;

    /// @notice Info of each pool user.
    mapping(uint256 => mapping(address => UserInfo)) public userInfo;
    /// @notice The whitelist of addresses allowed to deposit in special pools.
    mapping(address => bool) public whiteList;

    /// @notice Total regular allocation points. Must be the sum of all regular pools' allocation points.
    uint256 public totalRegularAllocPoint;
    /// @notice Total special allocation points. Must be the sum of all special pools' allocation points.
    uint256 public totalSpecialAllocPoint;
    uint256 public totalSlushsPerBlock = 1e17;
    uint256 public totalExtraPerBlock = 1e16;

    uint256 public constant ACC_REWARDS_PRECISION = 1e18;
    /// @notice Basic boost factor, none boosted user's boost factor
    uint256 public constant BOOST_PRECISION = 100 * 1e10;
    /// @notice Hard limit for maxmium boost factor, it must greater than BOOST_PRECISION
    uint256 public constant MAX_BOOST_PRECISION = 200 * 1e10;
    /// @notice Total rewards rate = toRegular + toSpecial
    uint256 public constant REWARDS_RATE_TOTAL_PRECISION = 1e12;
    /// @notice Rewards rate allocation for regular pools
    uint256 public regularFarmsRate = 1e12;
    /// @notice Rewards rate allocation for special pools
    uint256 public specialFarmsRate = 0;

    event AddPool(uint256 indexed pid, uint256 allocPoint, IERC20 indexed lpToken, bool isRegular);
    event SetPool(uint256 indexed pid, uint256 allocPoint);
    event UpdatePool(uint256 indexed pid, uint256 lastRewardBlock, uint256 lpSupply,
        uint256 accSlushPerShare, uint256 accExtraPerShare);
    event Deposit(address indexed user, uint256 indexed pid, uint256 amount);
    event Withdraw(address indexed user, uint256 indexed pid, uint256 amount);
    event EmergencyWithdraw(address indexed user, uint256 indexed pid, uint256 amount);

    event UpdateRates(uint256 regularFarmRate, uint256 specialFarmRate);
    event UpdateWhiteList(address indexed user, bool isValid);
    event UpdateBoostContract(address indexed boostContract);
    event UpdateBoostMultiplier(address indexed user, uint256 pid, uint256 oldMultiplier, uint256 newMultiplier);

    /// @param _SLUSH The SLUSH token contract address.
    /// @param _EXTRA The EXTRA token contract address.
    constructor(IERC20 _SLUSH, IERC20 _EXTRA) {
        SLUSH = _SLUSH;
        EXTRA = _EXTRA;
    }

    /**
     * @dev Throws if caller is not the boost contract.
     */
    modifier onlyBoostContract() {
        require(boostContract == msg.sender, "Ownable: caller is not the boost contract");
        _;
    }

    /// @notice Returns the number of MCV2 pools.
    function poolLength() public view returns (uint256 pools) {
        pools = poolInfo.length;
    }

    /// @notice Add a new pool. Can only be called by the owner.
    /// DO NOT add the same LP token more than once. Rewards will be messed up if you do.
    /// @param _allocPoint Number of allocation points for the new pool.
    /// @param _lpToken Address of the LP ERC-20 token.
    /// @param _isRegular Whether the pool is regular or special. LP farms are always "regular".
    /// "Special" pools are only for SLUSH distributions within  products.
    /// @param _withUpdate Whether call "massUpdatePools" operation.
    function add(
        uint256 _allocPoint,
        IERC20 _lpToken,
        bool _isRegular,
        bool _withUpdate
    ) external onlyOwner {
        require(_lpToken.balanceOf(address(this)) >= 0, "0 balance");
        // stake SLUSH token will cause staked token and reward token mixed up,
        // may cause staked tokens withdraw as reward token,never do it.
        require(_lpToken != SLUSH, "SLUSH token can't be added to farm pools");

        if (_withUpdate) {
            massUpdatePools();
        }

        if (_isRegular) {
            totalRegularAllocPoint = totalRegularAllocPoint.add(_allocPoint);
        } else {
            totalSpecialAllocPoint = totalSpecialAllocPoint.add(_allocPoint);
        }
        lpToken.push(_lpToken);

        poolInfo.push(
            PoolInfo({
                allocPoint: _allocPoint,
                lastRewardBlock: block.number,
                accSlushPerShare: 0,
                accExtraPerShare: 0,
                isRegular: _isRegular,
                totalBoostedShare: 0
            })
        );
        emit AddPool(lpToken.length.sub(1), _allocPoint, _lpToken, _isRegular);
    }

    /// @notice Update the given pool's SLUSH allocation point. Can only be called by the owner.
    /// @param _pid The id of the pool. See `poolInfo`.
    /// @param _allocPoint New number of allocation points for the pool.
    /// @param _withUpdate Whether call "massUpdatePools" operation.
    function set(
        uint256 _pid,
        uint256 _allocPoint,
        bool _withUpdate
    ) external onlyOwner {
        // No matter _withUpdate is true or false, we need to execute updatePool once before set the pool parameters.
        updatePool(_pid);

        if (_withUpdate) {
            massUpdatePools();
        }

        if (poolInfo[_pid].isRegular) {
            totalRegularAllocPoint = totalRegularAllocPoint.sub(poolInfo[_pid].allocPoint).add(_allocPoint);
        } else {
            totalSpecialAllocPoint = totalSpecialAllocPoint.sub(poolInfo[_pid].allocPoint).add(_allocPoint);
        }
        poolInfo[_pid].allocPoint = _allocPoint;
        emit SetPool(_pid, _allocPoint);
    }

    /// @notice View function for checking pending SLUSH rewards.
    /// @param _pid The id of the pool. See `poolInfo`.
    /// @param _user Address of the user.
    function pendingSlushs(uint256 _pid, address _user) external view returns (uint256) {
        return _pendingRewards(SLUSH, _pid, _user);
    }

    /// @notice View function for checking pending EXTRA rewards.
    /// @param _pid The id of the pool. See `poolInfo`.
    /// @param _user Address of the user.
    function pendingExtra(uint256 _pid, address _user) external view returns (uint256) {
        return _pendingRewards(EXTRA, _pid, _user);
    }

    function _pendingRewards(IERC20 _token, uint256 _pid, address _user) private view returns (uint256) {
        PoolInfo memory pool = poolInfo[_pid];
        UserInfo memory user = userInfo[_pid][_user];
        uint256 amountPerShare = _token == SLUSH ? pool.accSlushPerShare : pool.accExtraPerShare;
        uint256 lpSupply = pool.totalBoostedShare;

        if (block.number > pool.lastRewardBlock && lpSupply != 0) {
            uint256 multiplier = block.number.sub(pool.lastRewardBlock);
            uint256 amountPerBlock = _token == SLUSH ?
                slushPerBlock(pool.isRegular) : extraPerBlock(pool.isRegular);
            uint256 rewards = multiplier.mul(amountPerBlock).mul(pool.allocPoint).div(
                (pool.isRegular ? totalRegularAllocPoint : totalSpecialAllocPoint)
            );
            amountPerShare = amountPerShare.add(rewards.mul(ACC_REWARDS_PRECISION).div(lpSupply));
        }

        uint256 boostedAmount = user.amount.mul(getBoostMultiplier(_user, _pid)).div(BOOST_PRECISION);
        uint256 rewardDebt = _token == SLUSH ? user.rewardDebt : user.extraRewardDebt;
        return boostedAmount.mul(amountPerShare).div(ACC_REWARDS_PRECISION).sub(rewardDebt);
    }

    /// @notice Update SLUSH reward for all the active pools. Be careful of gas spending!
    function massUpdatePools() public {
        uint256 length = poolInfo.length;
        for (uint256 pid = 0; pid < length; ++pid) {
            PoolInfo memory pool = poolInfo[pid];
            if (pool.allocPoint != 0) {
                updatePool(pid);
            }
        }
    }

    function slushPerBlock(bool _isRegular) public view returns (uint256 amount) {
        return rewardsPerBlock(SLUSH, _isRegular);
    }

    function extraPerBlock(bool _isRegular) public view returns (uint256 amount) {
        return rewardsPerBlock(EXTRA, _isRegular);
    }

    /// @notice Calculates and returns the `amount` of rewards (SLUSH or EXTRA) per block.
    /// @param _token Either SLUSH or EXTRA.
    /// @param _isRegular If the pool belongs to regular or special.
    function rewardsPerBlock(IERC20 _token, bool _isRegular) private view returns (uint256 amount) {
        uint256 totalAmountPerBlock = _token == SLUSH ? totalSlushsPerBlock : totalExtraPerBlock;
        if (_isRegular) {
            amount = totalAmountPerBlock.mul(regularFarmsRate).div(REWARDS_RATE_TOTAL_PRECISION);
        } else {
            amount = totalAmountPerBlock.mul(specialFarmsRate).div(REWARDS_RATE_TOTAL_PRECISION);
        }
    }

    /// @notice Update reward variables for the given pool.
    /// @param _pid The id of the pool. See `poolInfo`.
    /// @return pool Returns the pool that was updated.
    function updatePool(uint256 _pid) public returns (PoolInfo memory pool) {
        pool = poolInfo[_pid];
        if (block.number > pool.lastRewardBlock) {
            uint256 lpSupply = pool.totalBoostedShare;
            uint256 totalAllocPoint = (pool.isRegular ? totalRegularAllocPoint : totalSpecialAllocPoint);

            if (lpSupply > 0 && totalAllocPoint > 0) {
                uint256 multiplier = block.number.sub(pool.lastRewardBlock);

                uint256 slushRewards = multiplier.mul(slushPerBlock(pool.isRegular))
                    .mul(pool.allocPoint).div(totalAllocPoint);
                pool.accSlushPerShare = pool.accSlushPerShare.add((slushRewards.mul(ACC_REWARDS_PRECISION).div(lpSupply)));
                
                uint256 extraRewards = multiplier.mul(extraPerBlock(pool.isRegular))
                    .mul(pool.allocPoint).div(totalAllocPoint);
                pool.accExtraPerShare = pool.accExtraPerShare.add((extraRewards.mul(ACC_REWARDS_PRECISION).div(lpSupply)));
            }
            pool.lastRewardBlock = block.number;
            poolInfo[_pid] = pool;
            emit UpdatePool(_pid, pool.lastRewardBlock, lpSupply, pool.accSlushPerShare, pool.accExtraPerShare);
        }
    }

    /// @notice Deposit LP tokens to pool.
    /// @param _pid The id of the pool. See `poolInfo`.
    /// @param _amount Amount of LP tokens to deposit.
    function deposit(uint256 _pid, uint256 _amount) external nonReentrant {
        PoolInfo memory pool = updatePool(_pid);
        UserInfo storage user = userInfo[_pid][msg.sender];

        require(
            pool.isRegular || whiteList[msg.sender],
            "MasterChefV2: The address is not available to deposit in this pool"
        );

        uint256 multiplier = getBoostMultiplier(msg.sender, _pid);

        if (user.amount > 0) {
            _settlePendingRewards(msg.sender, _pid, multiplier);
        }

        if (_amount > 0) {
            uint256 before = lpToken[_pid].balanceOf(address(this));
            lpToken[_pid].safeTransferFrom(msg.sender, address(this), _amount);
            _amount = lpToken[_pid].balanceOf(address(this)).sub(before);
            user.amount = user.amount.add(_amount);

            // Update total boosted share.
            pool.totalBoostedShare = pool.totalBoostedShare.add(_amount.mul(multiplier).div(BOOST_PRECISION));
        }

        user.rewardDebt = _calculateDebt(user.amount, multiplier, pool.accSlushPerShare);
        user.extraRewardDebt = _calculateDebt(user.amount, multiplier, pool.accExtraPerShare);
        poolInfo[_pid] = pool;

        emit Deposit(msg.sender, _pid, _amount);
    }

    /// @notice Withdraw LP tokens from pool.
    /// @param _pid The id of the pool. See `poolInfo`.
    /// @param _amount Amount of LP tokens to withdraw.
    function withdraw(uint256 _pid, uint256 _amount) external nonReentrant {
        PoolInfo memory pool = updatePool(_pid);
        UserInfo storage user = userInfo[_pid][msg.sender];

        require(user.amount >= _amount, "withdraw: Insufficient");

        uint256 multiplier = getBoostMultiplier(msg.sender, _pid);

        _settlePendingRewards(msg.sender, _pid, multiplier);

        if (_amount > 0) {
            user.amount = user.amount.sub(_amount);
            lpToken[_pid].safeTransfer(msg.sender, _amount);
        }

        user.rewardDebt = _calculateDebt(user.amount, multiplier, pool.accSlushPerShare);
        user.extraRewardDebt = _calculateDebt(user.amount, multiplier, pool.accExtraPerShare);
        poolInfo[_pid].totalBoostedShare = poolInfo[_pid].totalBoostedShare.sub(
            _amount.mul(multiplier).div(BOOST_PRECISION)
        );

        emit Withdraw(msg.sender, _pid, _amount);
    }

    /// @notice This calculation was extracted from the withdraw and deposit functions
    /// @param _userAmount amount from UserInfo (user.amount)
    /// @param _multiplier result of getBoostMultiplier(msg.sender, _pid)
    /// @param _amountPerShare PoolInfo accSlushPerShare or accExtraPerShare
    function _calculateDebt(
        uint256 _userAmount,
        uint256 _multiplier,
        uint256 _amountPerShare) private pure returns (uint256 amount)
    {
        return _userAmount.mul(_multiplier).div(BOOST_PRECISION).mul(_amountPerShare).div(ACC_REWARDS_PRECISION);
    }

    /// @notice Withdraw without caring about the rewards. EMERGENCY ONLY.
    /// @param _pid The id of the pool. See `poolInfo`.
    function emergencyWithdraw(uint256 _pid) external nonReentrant {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];

        uint256 amount = user.amount;
        user.amount = 0;
        user.rewardDebt = 0;
        user.extraRewardDebt = 0;
        uint256 boostedAmount = amount.mul(getBoostMultiplier(msg.sender, _pid)).div(BOOST_PRECISION);
        pool.totalBoostedShare = pool.totalBoostedShare > boostedAmount ? pool.totalBoostedShare.sub(boostedAmount) : 0;

        // Note: transfer can fail or succeed if `amount` is zero.
        lpToken[_pid].safeTransfer(msg.sender, amount);
        emit EmergencyWithdraw(msg.sender, _pid, amount);
    }

    /// @notice Update totalSlushsPerBlock (amount of SLUSH to distribute as rewards).
    /// @param _totalSlushsPerBlock The new total amount of SLUSH per block.
    /// @param _withUpdate Whether call "massUpdatePools" operation.
    function updateTotalSlushsPerBlock(
        uint256 _totalSlushsPerBlock,
        bool _withUpdate
    ) external onlyOwner {
        if (_withUpdate) {
            massUpdatePools();
        }

        totalSlushsPerBlock = _totalSlushsPerBlock;
    }

    /// @notice Update totalExtraPerBlock (amount of EXTRA to distribute as rewards).
    /// @param _totalExtraPerBlock The new total amount of EXTRA per block.
    /// @param _withUpdate Whether call "massUpdatePools" operation.
    function updateTotalExtraPerBlock(
        uint256 _totalExtraPerBlock,
        bool _withUpdate
    ) external onlyOwner {
        if (_withUpdate) {
            massUpdatePools();
        }

        totalExtraPerBlock = _totalExtraPerBlock;
    }

    /// @notice Update the rewards rates for regular pools and special pools.
    /// @param _regularFarmsRate The allocation to regular pools.
    /// @param _specialFarmsRate The allocation to special pools.
    /// @param _withUpdate Whether call "massUpdatePools" operation.
    function updateRates(
        uint256 _regularFarmsRate,
        uint256 _specialFarmsRate,
        bool _withUpdate
    ) external onlyOwner {
        require(
            _regularFarmsRate.add(_specialFarmsRate) == REWARDS_RATE_TOTAL_PRECISION,
            "MasterChefV2: Total rate must be 1e12"
        );
        if (_withUpdate) {
            massUpdatePools();
        }

        regularFarmsRate = _regularFarmsRate;
        specialFarmsRate = _specialFarmsRate;

        emit UpdateRates(_regularFarmsRate, _specialFarmsRate);
    }

    /// @notice Update whitelisted addresses for special pools.
    /// @param _user The address to be updated.
    /// @param _isValid The flag for valid or invalid.
    function updateWhiteList(address _user, bool _isValid) external onlyOwner {
        require(_user != address(0), "MasterChefV2: The white list address must be valid");

        whiteList[_user] = _isValid;
        emit UpdateWhiteList(_user, _isValid);
    }

    /// @notice Update boost contract address and max boost factor.
    /// @param _newBoostContract The new address for handling all the share boosts.
    function updateBoostContract(address _newBoostContract) external onlyOwner {
        require(
            _newBoostContract != address(0) && _newBoostContract != boostContract,
            "MasterChefV2: New boost contract address must be valid"
        );

        boostContract = _newBoostContract;
        emit UpdateBoostContract(_newBoostContract);
    }

    /// @notice Update user boost factor.
    /// @param _user The user address for boost factor updates.
    /// @param _pid The pool id for the boost factor updates.
    /// @param _newMultiplier New boost multiplier.
    function updateBoostMultiplier(
        address _user,
        uint256 _pid,
        uint256 _newMultiplier
    ) external onlyBoostContract nonReentrant {
        require(_user != address(0), "MasterChefV2: The user address must be valid");
        require(poolInfo[_pid].isRegular, "MasterChefV2: Only regular farm could be boosted");
        require(
            _newMultiplier >= BOOST_PRECISION && _newMultiplier <= MAX_BOOST_PRECISION,
            "MasterChefV2: Invalid new boost multiplier"
        );

        PoolInfo memory pool = updatePool(_pid);
        UserInfo storage user = userInfo[_pid][_user];

        uint256 prevMultiplier = getBoostMultiplier(_user, _pid);
        _settlePendingRewards(_user, _pid, prevMultiplier);

        user.rewardDebt = _calculateDebt(user.amount, _newMultiplier, pool.accSlushPerShare);
        user.extraRewardDebt = _calculateDebt(user.amount, _newMultiplier, pool.accExtraPerShare);
        pool.totalBoostedShare = pool.totalBoostedShare.sub(user.amount.mul(prevMultiplier).div(BOOST_PRECISION)).add(
            user.amount.mul(_newMultiplier).div(BOOST_PRECISION)
        );
        poolInfo[_pid] = pool;
        userInfo[_pid][_user].boostMultiplier = _newMultiplier;

        emit UpdateBoostMultiplier(_user, _pid, prevMultiplier, _newMultiplier);
    }

    /// @notice Get user boost multiplier for specific pool id.
    /// @param _user The user address.
    /// @param _pid The pool id.
    function getBoostMultiplier(address _user, uint256 _pid) public view returns (uint256) {
        uint256 multiplier = userInfo[_pid][_user].boostMultiplier;
        return multiplier > BOOST_PRECISION ? multiplier : BOOST_PRECISION;
    }

    /// @notice Settles & distributes the pending rewards for a given user.
    /// @param _user The user address.
    /// @param _pid The pool id.
    /// @param _boostMultiplier The user boost multiplier in a specific pool id.
    function _settlePendingRewards(
        address _user,
        uint256 _pid,
        uint256 _boostMultiplier
    ) internal {
        UserInfo memory user = userInfo[_pid][_user];
        uint256 boostedAmount = user.amount.mul(_boostMultiplier).div(BOOST_PRECISION);

        // Settle SLUSH
        uint256 accSlush = boostedAmount.mul(poolInfo[_pid].accSlushPerShare).div(ACC_REWARDS_PRECISION);
        uint256 slushToSend = accSlush.sub(user.rewardDebt);
        _safeTransfer(SLUSH, _user, slushToSend);

        // Settle EXTRA
        uint256 accExtra = boostedAmount.mul(poolInfo[_pid].accExtraPerShare).div(ACC_REWARDS_PRECISION);
        uint256 extraToSend = accExtra.sub(user.extraRewardDebt);
        _safeTransfer(EXTRA, _user, extraToSend);
    }

    /// @notice Safe Transfer reward token.
    /// @param _to The receiver address.
    /// @param _amount The amount to transfer.
    function _safeTransfer(IERC20 token, address _to, uint256 _amount) internal {
        if (_amount > 0) {
            uint256 balance = token.balanceOf(address(this));
            // Check whether MCV2 has enough token. If not, fail with an error.
            require(balance >= _amount, "_safeTransfer: Insufficient");
            token.safeTransfer(_to, _amount);
        }
    }
}