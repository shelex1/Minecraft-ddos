// Extract play-state CUSTOM_PAYLOAD packet ids per protocol version.
const mcdata = require('/home/agent/work/mcddos/node_modules/minecraft-data');
const versions = mcdata.getVersions('java', ['1.19', '1.19.1', '1.19.2', '1.19.3', '1.19.4',
  '1.20', '1.20.1', '1.20.2', '1.20.3', '1.20.4', '1.20.5', '1.20.6',
  '1.21', '1.21.1', '1.21.2', '1.21.3', '1.21.4', '1.21.5', '1.21.6',
  '1.21.7', '1.21.8', '1.21.9', '1.21.10', '1.21.11']);

const out = {};
for (const v of versions) {
  const p = v.protocol.version;
  const data = mcdata.getProtocol({ dataVersion: v.dataVersion });
  let s = null, c = null;
  for (const pkt of data.protocol.play.toClient) {
    if (pkt.name === 'custom_payload' || pkt.name === 'plugin_message') { s = pkt.type; break; }
  }
  for (const pkt of data.protocol.play.toServer) {
    if (pkt.name === 'custom_payload' || pkt.name === 'plugin_message') { c = pkt.type; break; }
  }
  // also configuration state custom payload
  let cs = null, cc = null;
  if (data.protocol.configuration) {
    for (const pkt of data.protocol.configuration.toClient) {
      if (pkt.name === 'custom_payload' || pkt.name === 'plugin_message') { cs = pkt.type; break; }
    }
    for (const pkt of data.protocol.configuration.toServer) {
      if (pkt.name === 'custom_payload' || pkt.name === 'plugin_message') { cc = pkt.type; break; }
    }
  }
  out[p] = { name: v.version, s2c: s, c2s: c, conf_s2c: cs, conf_c2s: cc };
}
console.log(JSON.stringify(out, null, 1));
