# JSLBot IP Permissions Auditor

The IP Permissions Auditor is an automated module within the JSLBot framework designed to scan an entire simulator for objects and embedded inventory items (scripts, geometry) with vulnerable "Next Owner" permissions.

This is extremely useful in roleplay or building environments where items must be restricted to prevent IP theft (e.g. flagging items that are left as Copy+Transfer, or scripts left as Modifiable).

## How It Works

The Auditor works by systematically sweeping a region to discover objects. Because the Second Life/OpenSim protocol only streams object data within a certain draw distance, the bot performs a grid sweep, teleporting to waypoints across the region.

When the bot discovers a new object:
1. **Root Object Check**: The bot dispatches a `RequestObjectPropertiesFamily` packet. This checks the mesh geometry itself to ensure the base object's "Next Owner" mask isn't set to both Copy and Transfer.
2. **Inner Inventory Check**: The bot dispatches a `RequestTaskInventory` packet.
   - Due to size limits, object inventories are usually transferred via the UDP Xfer protocol.
   - The bot receives a `ReplyTaskInventory` containing a filename.
   - It issues a `RequestXfer` and reassembles the binary payload from incoming `SendXferPacket`s.
   - It parses the resulting LLSD to evaluate the permissions of all embedded assets (e.g., textures, scripts, notecards).
3. **Evaluation**: Any item flagged as allowing both Copy and Transfer, or any script flagged as Modifiable, will be logged.

## Configuration & Usage

The Auditor module is enabled by default in `JSLBot.java` and `Test.java`. If you use custom configuration properties, make sure `Auditor` is listed in your `handlers=` property.

### Commands

Interact with the Auditor module via the JSLBot console or instant message commands:

#### `whitelistcreator <Creator-UUID>`
- **Description**: Adds a Creator UUID to the whitelist. The bot will ignore (skip inspecting) objects created/owned by this user. This is crucial to prevent false positives when residents wear/drop their own legally-owned items.
- **Example**: `whitelistcreator 96daa0f6-ed65-434d-814a-72e0eda7941e`
- *Note: This whitelist is saved to your configuration file and persists across bot restarts.*

#### `startaudit`
- **Description**: Begins the region sweep. The bot will automatically move around the simulator to discover objects and request their properties/inventories.
- **Example**: `startaudit`

## The Audit Report

Flagged vulnerabilities are appended to a file in your project root called `audit_report.csv`.
The report contains the following comma-separated fields:

1. **Object Name**
2. **Object UUID**
3. **Location (X, Y, Z)**
4. **Owner UUID**
5. **Flagged Sub-Item Name** (The name of the embedded item, or the root object itself)
6. **Permission State / Reason** (e.g. "Copy+Transfer", "Modifiable Script")

## Troubleshooting

- **The bot isn't finding any objects / the audit ends immediately**: Ensure your JSLBot is logged in and has successfully connected its primary circuit and EventQueue. The console should state that the sweep thread has started.
- **The console says "Unknown Command:whitelistcreator"**: Make sure you type the command entirely in lowercase. The JSLBot command parser is case-sensitive and normalizes input to lowercase.
- **I am getting a flood of false positives**: You likely have not whitelisted your primary builder or estate owner accounts. Use the `whitelistcreator` command to add trusted creators so the bot skips their items.
- **Transfers are timing out**: The UDP protocol is lossy. The Auditor has a built-in 10-second timeout for stalled Xfers to prevent the queue from deadlocking. Stalled items will simply be skipped and can be rescanned on a future audit.
