// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title TicketOffice
/// @notice Event ticketing: admin creates events, users buy tickets, transfer
///         them, or resell them on a per-ticket listing. Deliberately minimal:
///         no ERC721 — we keep only the data that must be trusted on chain.
contract TicketOffice {
    // ---- Types ----------------------------------------------------------
    struct Event {
        uint256 id;
        string  name;
        uint256 priceWei;      // primary-sale face price
        uint256 totalSupply;   // cap
        uint256 sold;          // issued so far
        uint256 eventDate;     // unix seconds; 0 means unset
        bool    exists;
        bool    active;        // admin can pause primary sales
    }

    struct Ticket {
        uint256 id;
        uint256 eventId;
        address owner;
        bool    exists;
    }

    struct Listing {
        uint256 priceWei;
        bool    active;
    }

    // ---- Storage --------------------------------------------------------
    address public owner;
    uint256 public nextEventId  = 1;
    uint256 public nextTicketId = 1;

    uint256[] private eventIds;
    mapping(uint256 => Event)   private events_;
    mapping(uint256 => Ticket)  private tickets;
    mapping(uint256 => Listing) private listings;       // ticketId => listing

    // ---- Errors ---------------------------------------------------------
    error NotOwner();
    error NotTicketOwner();
    error EventNotFound(uint256 id);
    error TicketNotFound(uint256 id);
    error EventInactive();
    error SoldOut();
    error InsufficientPayment(uint256 required, uint256 sent);
    error InvalidPrice();
    error InvalidSupply();
    error EmptyName();
    error ZeroAddress();
    error SelfTransfer();
    error NotListed();
    error AlreadyListed();
    error PaymentFailed();

    // ---- Events ---------------------------------------------------------
    event EventCreated(uint256 indexed id, string name, uint256 priceWei, uint256 totalSupply, uint256 eventDate);
    event EventActiveChanged(uint256 indexed id, bool active);
    event PriceUpdated(uint256 indexed id, uint256 oldPrice, uint256 newPrice);
    event TicketPurchased(uint256 indexed ticketId, uint256 indexed eventId, address indexed buyer, uint256 pricePaid);
    event TicketTransferred(uint256 indexed ticketId, address indexed from, address indexed to);
    event TicketListed(uint256 indexed ticketId, address indexed seller, uint256 priceWei);
    event ListingCancelled(uint256 indexed ticketId, address indexed seller);
    event TicketResold(uint256 indexed ticketId, address indexed from, address indexed to, uint256 pricePaid);

    // ---- Modifiers ------------------------------------------------------
    modifier onlyOwner()  { if (msg.sender != owner) revert NotOwner(); _; }

    constructor() { owner = msg.sender; }

    // ---- Admin ----------------------------------------------------------

    /// @notice Create a new event. Admin only.
    function createEvent(
        string calldata name,
        uint256 priceWei,
        uint256 totalSupply,
        uint256 eventDate
    ) external onlyOwner returns (uint256 id) {
        if (bytes(name).length == 0) revert EmptyName();
        if (priceWei    == 0) revert InvalidPrice();
        if (totalSupply == 0) revert InvalidSupply();

        id = nextEventId++;
        events_[id] = Event({
            id: id,
            name: name,
            priceWei: priceWei,
            totalSupply: totalSupply,
            sold: 0,
            eventDate: eventDate,
            exists: true,
            active: true
        });
        eventIds.push(id);
        emit EventCreated(id, name, priceWei, totalSupply, eventDate);
    }

    /// @notice Pause or resume primary sales for an event. Admin only.
    function setEventActive(uint256 id, bool active) external onlyOwner {
        Event storage e = events_[id];
        if (!e.exists) revert EventNotFound(id);
        e.active = active;
        emit EventActiveChanged(id, active);
    }

    /// @notice Update the primary-sale price of an event. Admin only.
    function updatePrice(uint256 id, uint256 newPriceWei) external onlyOwner {
        if (newPriceWei == 0) revert InvalidPrice();
        Event storage e = events_[id];
        if (!e.exists) revert EventNotFound(id);
        uint256 old = e.priceWei;
        e.priceWei = newPriceWei;
        emit PriceUpdated(id, old, newPriceWei);
    }

    /// @notice Withdraw primary-sale ETH to the owner. Admin only.
    function withdraw() external onlyOwner {
        (bool ok, ) = payable(owner).call{value: address(this).balance}("");
        if (!ok) revert PaymentFailed();
    }

    // ---- Primary purchase -----------------------------------------------

    /// @notice Buy one ticket for a given event at face price.
    function buyTicket(uint256 eventId) external payable returns (uint256 ticketId) {
        Event storage e = events_[eventId];
        if (!e.exists)  revert EventNotFound(eventId);
        if (!e.active)  revert EventInactive();
        if (e.sold >= e.totalSupply) revert SoldOut();
        if (msg.value < e.priceWei) revert InsufficientPayment(e.priceWei, msg.value);

        ticketId = nextTicketId++;
        tickets[ticketId] = Ticket({
            id: ticketId,
            eventId: eventId,
            owner: msg.sender,
            exists: true
        });
        e.sold += 1;

        uint256 refund = msg.value - e.priceWei;
        if (refund > 0) {
            (bool ok, ) = payable(msg.sender).call{value: refund}("");
            if (!ok) revert PaymentFailed();
        }
        emit TicketPurchased(ticketId, eventId, msg.sender, e.priceWei);
    }

    // ---- Transfer -------------------------------------------------------

    /// @notice Gift-transfer a ticket to another address. Owner only.
    function transferTicket(uint256 ticketId, address to) external {
        if (to == address(0)) revert ZeroAddress();
        Ticket storage t = tickets[ticketId];
        if (!t.exists) revert TicketNotFound(ticketId);
        if (t.owner != msg.sender) revert NotTicketOwner();
        if (to == msg.sender) revert SelfTransfer();

        // Clear any active listing so a transferred ticket can't still be bought.
        if (listings[ticketId].active) {
            delete listings[ticketId];
            emit ListingCancelled(ticketId, msg.sender);
        }

        address from = t.owner;
        t.owner = to;
        emit TicketTransferred(ticketId, from, to);
    }

    // ---- Resale ---------------------------------------------------------

    /// @notice List an owned ticket for resale at `priceWei`.
    function listForResale(uint256 ticketId, uint256 priceWei) external {
        if (priceWei == 0) revert InvalidPrice();
        Ticket storage t = tickets[ticketId];
        if (!t.exists) revert TicketNotFound(ticketId);
        if (t.owner != msg.sender) revert NotTicketOwner();
        if (listings[ticketId].active) revert AlreadyListed();

        listings[ticketId] = Listing({priceWei: priceWei, active: true});
        emit TicketListed(ticketId, msg.sender, priceWei);
    }

    /// @notice Cancel your own resale listing.
    function cancelListing(uint256 ticketId) external {
        Ticket storage t = tickets[ticketId];
        if (!t.exists) revert TicketNotFound(ticketId);
        if (t.owner != msg.sender) revert NotTicketOwner();
        if (!listings[ticketId].active) revert NotListed();

        delete listings[ticketId];
        emit ListingCancelled(ticketId, msg.sender);
    }

    /// @notice Buy a listed ticket on the secondary market. Payment flows to
    ///         the seller (no fee taken on purpose to keep the contract simple).
    function buyResale(uint256 ticketId) external payable {
        Ticket  storage t = tickets[ticketId];
        Listing storage l = listings[ticketId];
        if (!t.exists)   revert TicketNotFound(ticketId);
        if (!l.active)   revert NotListed();
        if (msg.value < l.priceWei) revert InsufficientPayment(l.priceWei, msg.value);
        if (t.owner == msg.sender) revert SelfTransfer();

        address seller = t.owner;
        uint256 price  = l.priceWei;

        // Effects
        t.owner = msg.sender;
        delete listings[ticketId];

        // Interactions
        (bool ok, ) = payable(seller).call{value: price}("");
        if (!ok) revert PaymentFailed();

        uint256 refund = msg.value - price;
        if (refund > 0) {
            (bool ok2, ) = payable(msg.sender).call{value: refund}("");
            if (!ok2) revert PaymentFailed();
        }
        emit TicketResold(ticketId, seller, msg.sender, price);
    }

    // ---- Views ----------------------------------------------------------

    function eventCount() external view returns (uint256) { return eventIds.length; }
    function allEventIds() external view returns (uint256[] memory) { return eventIds; }

    function getEvent(uint256 id) external view returns (
        uint256 eid, string memory name, uint256 priceWei,
        uint256 totalSupply, uint256 sold, uint256 eventDate, bool active
    ) {
        Event storage e = events_[id];
        if (!e.exists) revert EventNotFound(id);
        return (e.id, e.name, e.priceWei, e.totalSupply, e.sold, e.eventDate, e.active);
    }

    function getTicket(uint256 ticketId) external view returns (
        uint256 tid, uint256 eventId, address ticketOwner
    ) {
        Ticket storage t = tickets[ticketId];
        if (!t.exists) revert TicketNotFound(ticketId);
        return (t.id, t.eventId, t.owner);
    }

    function getListing(uint256 ticketId) external view returns (uint256 priceWei, bool active) {
        Listing storage l = listings[ticketId];
        return (l.priceWei, l.active);
    }

    /// @notice Return all ticket ids owned by `who`. O(n) over all issued tickets.
    ///         Fine for the demo; a production system would index via events.
    function ticketsOf(address who) external view returns (uint256[] memory owned) {
        uint256 total = nextTicketId - 1;
        uint256 count;
        for (uint256 i = 1; i <= total; i++) {
            if (tickets[i].exists && tickets[i].owner == who) count++;
        }
        owned = new uint256[](count);
        uint256 k;
        for (uint256 i = 1; i <= total; i++) {
            if (tickets[i].exists && tickets[i].owner == who) {
                owned[k++] = i;
            }
        }
    }
}
