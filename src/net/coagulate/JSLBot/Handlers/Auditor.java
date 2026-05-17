package net.coagulate.JSLBot.Handlers;

import net.coagulate.JSLBot.*;
import net.coagulate.JSLBot.JSLBot.CmdHelp;
import net.coagulate.JSLBot.JSLBot.Param;
import net.coagulate.JSLBot.Packets.Messages.*;
import net.coagulate.JSLBot.Packets.Types.*;
import net.coagulate.JSLBot.LLSD.*;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.io.File;
import java.text.SimpleDateFormat;

public class Auditor extends Handler implements Runnable {
	private final Set<Integer> processedObjects = ConcurrentHashMap.newKeySet();
	private final Map<LLUUID, ObjectData> pendingInventoryRequests = new ConcurrentHashMap<>();
	private final Map<String, LLUUID> filenameToTask = new ConcurrentHashMap<>();
	private final ConcurrentLinkedQueue<ObjectData> inspectionQueue = new ConcurrentLinkedQueue<>();
	private final AtomicBoolean isAuditing = new AtomicBoolean(false);

	private final Set<String> reportedVulnerabilities = ConcurrentHashMap.newKeySet();

	private final Set<LLUUID> objectWhitelist = new HashSet<>();

	private String currentAuditReportFile = "audit_report.csv";

	// Traversal settings
	private static final float GRID_MIN_X = 16.0f;
	private static final float GRID_MAX_X = 240.0f;
	private static final float GRID_MIN_Y = 16.0f;
	private static final float GRID_MAX_Y = 240.0f;
	private static final float GRID_MIN_Z = 20.0f;
	private static final float GRID_MAX_Z = 4096.0f;
	private static final float GRID_STEP = 64.0f;
	private static final float GRID_STEP_Z = 64.0f;

	public Auditor(@Nonnull final JSLBot bot, final Configuration config) {
		super(bot, config);
		String whitelist = config.get("objectWhitelist", "");
		if (!whitelist.isEmpty()) {
			for (String uuidStr : whitelist.split(",")) {
				objectWhitelist.add(new LLUUID(uuidStr));
			}
		}
	}

	private void saveWhitelist() {
		StringBuilder sb = new StringBuilder();
		for (LLUUID uuid : objectWhitelist) {
			if (sb.length() > 0) sb.append(",");
			sb.append(uuid.toString());
		}
		config.put("objectWhitelist", sb.toString());
	}

	@Override
	public void loggedIn() {
		Thread t = new Thread(this);
		t.setName("Auditor Thread");
		t.start();
	}

	@Override
	public void run() {
		while (true) {
			if (isAuditing.get()) {
				// Process inspection queue (throttle to avoid flooding)
				processInspectionQueue();
			}
			try {
				Thread.sleep(50); // 20 times a second
			} catch (InterruptedException e) {
				break;
			}
			cleanupStaleXfers();
		}
	}

	private void cleanupStaleXfers() {
		long now = System.currentTimeMillis();
		List<Long> toRemove = new ArrayList<>();
		for (Map.Entry<Long, Long> entry : xferTimestamps.entrySet()) {
			if (now - entry.getValue() > 10000) { // 10 seconds timeout
				toRemove.add(entry.getKey());
			}
		}
		for (Long staleXfer : toRemove) {
			xferTimestamps.remove(staleXfer);
			activeXfers.remove(staleXfer);
			System.out.println("Cleaned up stale xfer: " + staleXfer);
		}
	}

	public void objectPropertiesFamilyUDPImmediate(@Nonnull final UDPEvent event) {
		@Nonnull final ObjectPropertiesFamily object=(ObjectPropertiesFamily)event.body();
		int nextOwnerMask = object.bobjectdata.vnextownermask.value;
		int everyoneMask = object.bobjectdata.veveryonemask.value;
		int groupMask = object.bobjectdata.vgroupmask.value;

		LLUUID objectId = object.bobjectdata.vobjectid;
		String name = object.bobjectdata.vname.toString();

		boolean publicTheft = (everyoneMask & 0x00008000) != 0;
		boolean publicGriefing = (everyoneMask & 0x00080000) != 0;
		boolean groupTheft = (groupMask & 0x00008000) != 0;
		boolean groupTampering = (groupMask & 0x00004000) != 0;

		boolean noTransfer = (nextOwnerMask & 0x00002000) != 0;
		boolean noCopy = (nextOwnerMask & 0x00008000) != 0;
		boolean noModify = (nextOwnerMask & 0x00004000) != 0;

		boolean accidentalFullPerm = publicTheft && (noCopy && noTransfer && noModify);

		// Note: We don't have invType here, so we skip the script specific checks
		// for the root object since it's an object, not a script item.

		if (objectWhitelist.contains(objectId)) {
			return; // Whitelisted object, skip logging
		}

		if (publicTheft || publicGriefing || groupTheft || groupTampering || accidentalFullPerm) {
			String reason = "";
			if (publicTheft) reason += "Root Object Public Theft Risk ";
			if (publicGriefing) reason += "Root Object Public Griefing Risk ";
			if (groupTheft) reason += "Root Object Group Theft Risk ";
			if (groupTampering) reason += "Root Object Group Tampering Risk ";
			if (accidentalFullPerm) reason += "Root Object IP Risk: Accidental Full Perm ";

			System.out.println("VULNERABILITY FOUND: " + name + " - " + reason);
			String owner = object.bobjectdata.vownerid.toString();
			ObjectData od = event.region().getObject(object.bobjectdata.vobjectid);
			String location = "Unknown Loc";
			if (od != null && od.getX() >= 0 && od.getY() >= 0 && od.getZ() >= 0) {
				location = String.format("secondlife://%s/%.0f/%.0f/%.0f", bot.getRegionName(), od.getX(), od.getY(), od.getZ());
			}
			logVulnerability(name, objectId.toString(), location, owner, name, reason);
		}
	}

	@Nonnull
	@CmdHelp(description="Add object to whitelist")
	public String whitelistobjectCommand(@Nonnull final CommandEvent command,
										  @Nonnull @Param(name="objectuuid", description="Object UUID") final String objectuuid) {
		objectWhitelist.add(new LLUUID(objectuuid));
		saveWhitelist();
		return "Added to whitelist.";
	}

	@Nonnull
	@CmdHelp(description="Start the IP permissions audit sweep")
	public String startAuditCommand(@Nonnull final CommandEvent command) {
		if (isAuditing.compareAndSet(false, true)) {
			SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd_HHmmss");
			currentAuditReportFile = "audit_report_" + sdf.format(new Date()) + ".csv";

			try (PrintWriter out = new PrintWriter(new FileWriter(currentAuditReportFile, false))) {
				out.println("Object Name,Object UUID,Location,Owner,SubItem Name,Reason");
			} catch (IOException e) {
				System.err.println("Failed to initialize audit report: " + e.getMessage());
			}

			Thread sweepThread = new Thread(() -> sweepGrid());
			sweepThread.setName("Auditor Sweep Thread");
			sweepThread.start();
			return "Audit sweep started. Logging to " + currentAuditReportFile;
		} else {
			return "Audit sweep is already running.";
		}
	}

	private void sweepGrid() {
		try {
			// Fly around the grid to discover objects
			for (float z = GRID_MIN_Z; z <= GRID_MAX_Z; z += GRID_STEP_Z) {
				for (float x = GRID_MIN_X; x <= GRID_MAX_X; x += GRID_STEP) {
					for (float y = GRID_MIN_Y; y <= GRID_MAX_Y; y += GRID_STEP) {
						if (!isAuditing.get()) return;
						// Physically teleport the bot to ensure object discovery streams all sim objects
						TeleportLocationRequest tp = new TeleportLocationRequest();
						tp.bagentdata.vagentid = bot.getUUID();
						tp.bagentdata.vsessionid = bot.getSession();
						tp.binfo.vposition = new LLVector3(x, y, z);
						tp.binfo.vlookat = new LLVector3(x + 1.0f, y, z);
						tp.binfo.vregionhandle = new U64();
						tp.binfo.vregionhandle.value = bot.getRegional().handle();
						bot.send(tp, true);

						System.out.println("Sweeping position: " + x + ", " + y + ", " + z + " | Objects reviewed: " + processedObjects.size());

						// Wait for the teleport to complete over the async network protocol.
						// This prevents "CouldntTPCloser" errors that happen when sending agent movement completes
						// immediately after teleporting before the sim is ready.
						Thread.sleep(5000);
						bot.setPos(x, y, z); // Update height
						bot.forceAgentUpdate();
					}
				}
			}

			// Drain phase: wait for the inspection queue to process all known objects
			System.out.println("Sweep complete. Draining queue...");
			while (!inspectionQueue.isEmpty()) {
				Thread.sleep(1000);
			}

			// Network grace period for trailing UDP packets
			System.out.println("Queue drained. Waiting for trailing network updates...");
			Thread.sleep(5000);

			// Safely clean up
			System.out.println("Audit sweep ended run. Total objects reviewed: " + processedObjects.size());
			currentAuditReportFile = "audit_report.csv"; // reset to default
			reportedVulnerabilities.clear();
			processedObjects.clear();
			pendingInventoryRequests.clear();
			filenameToTask.clear();
			xferFileToObject.clear();
			activeXfers.clear();
			xferTimestamps.clear();
			isAuditing.set(false);
		} catch (InterruptedException e) {
			System.out.println("Sweep interrupted.");
		}
	}

	// Hook into object discovery
	public void objectUpdateUDPImmediate(@Nonnull final UDPEvent event) {
		@Nonnull final ObjectUpdate data=(ObjectUpdate)event.body();
		for (@Nonnull final ObjectUpdate_bObjectData obj: data.bobjectdata) {
			queueForInspection(event.region().getObject(obj.vid.value));
		}
	}

	public void objectUpdateCachedUDPImmediate(@Nonnull final UDPEvent event) {
		@Nonnull final ObjectUpdateCached objectUpdateCached=(ObjectUpdateCached)event.body();
		for (@Nonnull final ObjectUpdateCached_bObjectData data: objectUpdateCached.bobjectdata) {
			final int id=data.vid.value;
			if (event.region().hasObject(id)) {
				queueForInspection(event.region().getObject(id));
			}
		}
	}

	public void objectUpdateCompressedUDPImmediate(@Nonnull final UDPEvent event) {
		@Nonnull final ObjectUpdateCompressed ouc=(ObjectUpdateCompressed)event.body();
		for (@Nonnull final ObjectUpdateCompressed_bObjectData data: ouc.bobjectdata) {
			@Nonnull final ByteBuffer buffer=ByteBuffer.wrap(data.vdata.value);
			@Nonnull final LLUUID uuid=new LLUUID(buffer);
			final int localid=new U32(buffer).value;
			if (event.region().hasObject(localid)) {
				queueForInspection(event.region().getObject(localid));
			}
		}
	}

	public void multipleObjectUpdateUDPImmediate(@Nonnull final UDPEvent event) {
		@Nonnull final MultipleObjectUpdate msg=(MultipleObjectUpdate)event.body();
		for (@Nonnull final MultipleObjectUpdate_bObjectData data: msg.bobjectdata) {
			final int localid = data.vobjectlocalid.value;
			if (event.region().hasObject(localid)) {
				queueForInspection(event.region().getObject(localid));
			}
		}
	}

	private void queueForInspection(ObjectData od) {
		if (od != null && isAuditing.get()) {
			if (processedObjects.add(od.id.value)) { // returns true if not already present
				inspectionQueue.add(od);
			}
		}
	}

	private void processInspectionQueue() {
		ObjectData od = inspectionQueue.poll();
		if (od != null && od.fullid != null) {

			// Request root object properties for geometry checking
			RequestObjectPropertiesFamily propReq = new RequestObjectPropertiesFamily();
			propReq.bagentdata.vagentid = bot.getUUID();
			propReq.bagentdata.vsessionid = bot.getSession();
			propReq.bobjectdata.vobjectid = od.fullid;
			propReq.bobjectdata.vrequestflags = od.id;
			bot.send(propReq, true);

			// Ask for the task inventory
			pendingInventoryRequests.put(od.fullid, od);
			RequestTaskInventory req = new RequestTaskInventory();
			req.bagentdata.vagentid = bot.getUUID();
			req.bagentdata.vsessionid = bot.getSession();
			req.binventorydata.vlocalid = od.id;
			bot.send(req, true);
		}
	}

	// Map of filename -> object data, to associate xfer with the object
	private final Map<String, ObjectData> xferFileToObject = new ConcurrentHashMap<>();
	// Map of xfer id -> byte array stream (we'll just use a byte array builder)
	private final Map<Long, List<byte[]>> activeXfers = new ConcurrentHashMap<>();
	// Track timestamp of active transfers to manage timeouts
	private final Map<Long, Long> xferTimestamps = new ConcurrentHashMap<>();

	public void replyTaskInventoryUDPImmediate(@Nonnull final UDPEvent event) {
		@Nonnull final ReplyTaskInventory msg = (ReplyTaskInventory)event.body();
		String filename = msg.binventorydata.vfilename.toString();
		LLUUID taskid = msg.binventorydata.vtaskid;
		if (filename != null && !filename.isEmpty()) {
			if (taskid != null) {
				filenameToTask.put(filename, taskid);
			}
			// Issue RequestXfer
			RequestXfer req = new RequestXfer();
			req.bxferid.vid = new U64("0"); // Server uses 0 for a new request ID usually
			req.bxferid.vfilename = msg.binventorydata.vfilename;
			req.bxferid.vfilepath = new U8(0);
			req.bxferid.vdeleteoncompletion = new BOOL();
			req.bxferid.vdeleteoncompletion.value = 0;
			req.bxferid.vusebigpackets = new BOOL();
			req.bxferid.vusebigpackets.value = 0;
			req.bxferid.vvfileid = new LLUUID();
			req.bxferid.vvfiletype = new S16();
			req.bxferid.vvfiletype.value = (short)0;

			bot.send(req, true);
		}
	}

	public void sendXferPacketUDPImmediate(@Nonnull final UDPEvent event) {
		@Nonnull final SendXferPacket msg = (SendXferPacket)event.body();
		long xferId = msg.bxferid.vid.value;
		int packetNum = msg.bxferid.vpacket.value;
		byte[] data = msg.bdatapacket.vdata.value;

		// The protocol sets the MSB (highest bit) of packet number for the final packet.
		boolean isFinal = (packetNum & 0x80000000) != 0;
		packetNum = packetNum & 0x7FFFFFFF;

		activeXfers.computeIfAbsent(xferId, k -> new ArrayList<>()).add(data);
		xferTimestamps.put(xferId, System.currentTimeMillis());

		// Acknowledge
		ConfirmXferPacket ack = new ConfirmXferPacket();
		ack.bxferid.vid = msg.bxferid.vid;
		ack.bxferid.vpacket = msg.bxferid.vpacket; // Use raw packet number for ACK
		bot.send(ack, true);

		if (isFinal) {
			xferTimestamps.remove(xferId);
			List<byte[]> chunks = activeXfers.remove(xferId);
			if (chunks != null) {
				int totalLength = chunks.stream().mapToInt(c -> c.length).sum();
				byte[] fullPayload = new byte[totalLength];
				int offset = 0;
				for (byte[] chunk : chunks) {
					System.arraycopy(chunk, 0, fullPayload, offset, chunk.length);
					offset += chunk.length;
				}
				processTaskInventory(xferId, fullPayload);
			}
		}
	}

	private void processTaskInventory(long xferId, byte[] fullPayload) {
		try {
			// Extract LLSD representation of the inventory tree
			String llsdString = new String(fullPayload, "UTF-8");
			LLSD document = new LLSD(llsdString);
			if (document.getFirst() instanceof LLSDMap) {
				LLSDMap topLevel = (LLSDMap)document.getFirst();
				if (topLevel.get("folders") instanceof LLSDArray) {
					LLSDArray folders = (LLSDArray)topLevel.get("folders");
					for (Atomic folderAtomic : folders.get()) {
						if (folderAtomic instanceof LLSDMap) {
							LLSDMap folder = (LLSDMap)folderAtomic;
							if (folder.get("items") instanceof LLSDArray) {
								LLSDArray items = (LLSDArray)folder.get("items");
								for (Atomic itemAtomic : items.get()) {
									if (itemAtomic instanceof LLSDMap) {
										LLSDMap item = (LLSDMap)itemAtomic;
										int invType = ((LLSDInteger)item.get("inv_type")).get();
										int type = ((LLSDInteger)item.get("type")).get();
										int nextOwnerMask = 0;
										int everyoneMask = 0;
										int groupMask = 0;
										Atomic permissions = item.get("permissions");
										if (permissions instanceof LLSDMap) {
											LLSDMap permsMap = (LLSDMap)permissions;
											Atomic nextOwnerAtomic = permsMap.get("next_owner_mask");
											if (nextOwnerAtomic instanceof LLSDInteger) {
												nextOwnerMask = ((LLSDInteger)nextOwnerAtomic).get();
											}
											Atomic everyoneAtomic = permsMap.get("everyone_mask");
											if (everyoneAtomic instanceof LLSDInteger) {
												everyoneMask = ((LLSDInteger)everyoneAtomic).get();
											}
											Atomic groupAtomic = permsMap.get("group_mask");
											if (groupAtomic instanceof LLSDInteger) {
												groupMask = ((LLSDInteger)groupAtomic).get();
											}
										}

										String name = item.get("name").toString();
										String objectUUID = item.get("parent_id").toString(); // Usually the object ID when talking about task inventory

										// SL Permissions:
										// PERM_TRANSFER = 0x00002000 (8192)
										// PERM_COPY =     0x00008000 (32768)
										// PERM_MODIFY =   0x00004000 (16384)
										// PERM_MOVE =     0x00080000 (524288)

										boolean publicTheft = (everyoneMask & 0x00008000) != 0;
										boolean publicGriefing = (everyoneMask & 0x00080000) != 0;
										boolean groupTheft = (groupMask & 0x00008000) != 0;
										boolean groupTampering = (groupMask & 0x00004000) != 0;

										boolean noTransfer = (nextOwnerMask & 0x00002000) != 0;
										boolean noCopy = (nextOwnerMask & 0x00008000) != 0;
										boolean noModify = (nextOwnerMask & 0x00004000) != 0;

										boolean accidentalFullPerm = publicTheft && (noCopy && noTransfer && noModify);

										boolean isScript = (invType == 10);
										boolean liveScriptTampering = isScript && ((groupMask & 0x00004000) != 0 || (everyoneMask & 0x00004000) != 0);
										boolean sourceCodeLeak = isScript && noModify;

										LLUUID objId = new LLUUID(objectUUID);
										if (objectWhitelist.contains(objId)) {
											continue; // Whitelisted object, skip logging
										}

										if (publicTheft || publicGriefing || groupTheft || groupTampering || accidentalFullPerm || liveScriptTampering || sourceCodeLeak) {
											String reason = "";
											if (publicTheft) reason += "Public Theft Risk ";
											if (publicGriefing) reason += "Public Griefing Risk ";
											if (groupTheft) reason += "Group Theft Risk ";
											if (groupTampering) reason += "Group Tampering Risk ";
											if (accidentalFullPerm) reason += "IP Risk: Accidental Full Perm ";
											if (liveScriptTampering) reason += "Live Script Tampering Risk ";
											if (sourceCodeLeak) reason += "IP Risk: Exposed LSL Source Code ";

											System.out.println("VULNERABILITY FOUND: " + name + " - " + reason);
											ObjectData od = pendingInventoryRequests.get(objId);
											String objName = od != null && od.name != null ? od.name : "Unknown";
											String location = "Unknown Loc";
											if (od != null && od.getX() >= 0 && od.getY() >= 0 && od.getZ() >= 0) {
												location = String.format("secondlife://%s/%.0f/%.0f/%.0f", bot.getRegionName(), od.getX(), od.getY(), od.getZ());
											}
											String owner = od != null && od.owner != null ? od.owner.toString() : "Unknown Owner";
											logVulnerability(objName, objectUUID, location, owner, name, reason);
										}
									}
								}
							}
						}
					}
				}
			}
		} catch (Exception e) {
			System.err.println("Failed to parse task inventory: " + e.getMessage());
		}
	}

	private void logVulnerability(String objectName, String objectUUID, String location, String owner, String subItemName, String reason) {
		String compositeKey = objectUUID + ":" + subItemName + ":" + reason;
		if (!reportedVulnerabilities.add(compositeKey)) {
			return; // Duplicate vulnerability
		}

		try (PrintWriter out = new PrintWriter(new FileWriter(currentAuditReportFile, true))) {
			out.println(String.format("%s,%s,%s,%s,%s,%s",
				objectName, // Object Name
				objectUUID,
				location, // Location
				owner, // Owner
				subItemName,
				reason
			));
		} catch (IOException e) {
			System.err.println("Failed to log vulnerability: " + e.getMessage());
		}
	}
}
