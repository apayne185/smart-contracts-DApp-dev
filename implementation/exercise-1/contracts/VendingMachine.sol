// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title VendingMachine
/// @notice A simple on-chain vending machine that sells digital products.
/// @dev On chain we keep only what is required for trust:
///      product catalog (id, name, price, stock) and per-buyer ownership counts.
///      Heavy descriptions, images, etc. belong off chain.
contract VendingMachine {
    // ---- Types ----------------------------------------------------------
    struct Product {
        uint256 id;
        string  name;
        uint256 priceWei;
        uint256 stock;
        bool    exists;
    }

    // ---- Storage --------------------------------------------------------
    address public owner;
    uint256 public nextProductId = 1;
    uint256[] private productIds;
    mapping(uint256 => Product) private products;
    // buyer => productId => quantity owned (purchased through this machine)
    mapping(address => mapping(uint256 => uint256)) private ownedQty;

    // ---- Errors ---------------------------------------------------------
    error NotOwner();
    error ProductNotFound(uint256 id);
    error ProductAlreadyExists(uint256 id);
    error InvalidQuantity();
    error InvalidPrice();
    error EmptyName();
    error InsufficientPayment(uint256 required, uint256 sent);
    error InsufficientStock(uint256 available, uint256 requested);
    error RefundFailed();
    error WithdrawFailed();

    // ---- Events ---------------------------------------------------------
    event ProductAdded(uint256 indexed id, string name, uint256 priceWei, uint256 stock);
    event ProductRestocked(uint256 indexed id, uint256 addedQty, uint256 newStock);
    event PriceUpdated(uint256 indexed id, uint256 oldPrice, uint256 newPrice);
    event ProductPurchased(
        address indexed buyer,
        uint256 indexed id,
        uint256 qty,
        uint256 totalPaid
    );
    event Withdrawal(address indexed to, uint256 amount);

    // ---- Modifiers ------------------------------------------------------
    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // ---- Admin functions ------------------------------------------------

    /// @notice Add a brand new product to the machine. Admin only.
    function addProduct(string calldata name, uint256 priceWei, uint256 initialStock)
        external
        onlyOwner
        returns (uint256 id)
    {
        if (bytes(name).length == 0) revert EmptyName();
        if (priceWei == 0) revert InvalidPrice();

        id = nextProductId++;
        products[id] = Product({
            id: id,
            name: name,
            priceWei: priceWei,
            stock: initialStock,
            exists: true
        });
        productIds.push(id);
        emit ProductAdded(id, name, priceWei, initialStock);
    }

    /// @notice Add stock to an existing product. Admin only.
    function restock(uint256 id, uint256 addedQty) external onlyOwner {
        if (addedQty == 0) revert InvalidQuantity();
        Product storage p = products[id];
        if (!p.exists) revert ProductNotFound(id);
        p.stock += addedQty;
        emit ProductRestocked(id, addedQty, p.stock);
    }

    /// @notice Update the price of an existing product. Admin only.
    function updatePrice(uint256 id, uint256 newPriceWei) external onlyOwner {
        if (newPriceWei == 0) revert InvalidPrice();
        Product storage p = products[id];
        if (!p.exists) revert ProductNotFound(id);
        uint256 old = p.priceWei;
        p.priceWei = newPriceWei;
        emit PriceUpdated(id, old, newPriceWei);
    }

    /// @notice Withdraw collected ETH to the owner. Admin only.
    function withdraw() external onlyOwner {
        uint256 bal = address(this).balance;
        (bool ok, ) = payable(owner).call{value: bal}("");
        if (!ok) revert WithdrawFailed();
        emit Withdrawal(owner, bal);
    }

    // ---- User functions -------------------------------------------------

    /// @notice Buy `qty` units of product `id`. Refunds any overpayment.
    function purchase(uint256 id, uint256 qty) external payable {
        if (qty == 0) revert InvalidQuantity();
        Product storage p = products[id];
        if (!p.exists) revert ProductNotFound(id);
        if (p.stock < qty) revert InsufficientStock(p.stock, qty);

        uint256 cost = p.priceWei * qty;
        if (msg.value < cost) revert InsufficientPayment(cost, msg.value);

        // Effects
        p.stock -= qty;
        ownedQty[msg.sender][id] += qty;

        // Refund overpayment
        uint256 refund = msg.value - cost;
        if (refund > 0) {
            (bool ok, ) = payable(msg.sender).call{value: refund}("");
            if (!ok) revert RefundFailed();
        }

        emit ProductPurchased(msg.sender, id, qty, cost);
    }

    // ---- Views ----------------------------------------------------------

    /// @notice Return how many distinct products exist.
    function productCount() external view returns (uint256) {
        return productIds.length;
    }

    /// @notice Return all product ids (small catalog assumed).
    function allProductIds() external view returns (uint256[] memory) {
        return productIds;
    }

    /// @notice Get a product by id.
    function getProduct(uint256 id)
        external
        view
        returns (uint256 pid, string memory name, uint256 priceWei, uint256 stock)
    {
        Product storage p = products[id];
        if (!p.exists) revert ProductNotFound(id);
        return (p.id, p.name, p.priceWei, p.stock);
    }

    /// @notice How many units of product `id` are owned by `user`.
    function balanceOf(address user, uint256 id) external view returns (uint256) {
        return ownedQty[user][id];
    }
}
