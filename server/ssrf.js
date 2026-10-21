"use strict";
// Address policy for outgoing requests: only public unicast addresses.
const net = require("node:net");
const dns = require("node:dns");

const BLOCKED_V4 = [
	["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
	["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
	["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24],
	["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4]
];
// Includes IPv4-mapped, NAT64, 6to4 and Teredo, which can embed internal IPv4 targets.
const BLOCKED_V6 = [
	["::", 96], ["::ffff:0:0", 96], ["::ffff:0:0:0", 96], ["64:ff9b::", 96], ["64:ff9b:1::", 48],
	["100::", 64], ["2001::", 23], ["2001:db8::", 32], ["2002::", 16], ["3fff::", 20],
	["fc00::", 7], ["fe80::", 10], ["fec0::", 10], ["ff00::", 8]
];

// Separate lists: a BlockList also matches IPv4 addresses against IPv6 rules
// (as ::ffff:a.b.c.d), so ::ffff:0:0/96 would otherwise block every IPv4 address.
const v4 = new net.BlockList();
const v6 = new net.BlockList();
BLOCKED_V4.forEach(([a, p]) => v4.addSubnet(a, p, "ipv4"));
BLOCKED_V6.forEach(([a, p]) => v6.addSubnet(a, p, "ipv6"));

function isBlockedAddress(address) {
	const family = net.isIP(address);
	if (family === 4) return v4.check(address, "ipv4");
	if (family === 6) return v6.check(address, "ipv6");
	return true;
}

/**
 * Drop-in for the `lookup` option of http(s).request. The address check runs
 * at connect time on the address that is actually used, so DNS rebinding
 * between a "check" and the "connect" is not possible.
 */
function guardedLookup(hostname, options, callback) {
	if (typeof options === "function") {
		callback = options;
		options = {};
	}
	dns.lookup(hostname, { all: true, family: options.family || 0 }, (err, addresses) => {
		if (err) return callback(err);
		const blocked = addresses.find((a) => isBlockedAddress(a.address));
		if (blocked || addresses.length === 0) {
			const e = new Error(`blocked address for ${hostname}`);
			e.code = "EBLOCKED";
			return callback(e);
		}
		if (options.all) return callback(null, addresses);
		callback(null, addresses[0].address, addresses[0].family);
	});
}

module.exports = { isBlockedAddress, guardedLookup };
