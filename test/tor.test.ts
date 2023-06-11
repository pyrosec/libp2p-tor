import { Registry } from "../src.ts/registry.js";
import { Proxy } from "../src.ts/proxy.js";
import { Router } from "../src.ts/router";
import { equals } from "uint8arrays";
import { expect } from "chai";
import { Cell, CellCommand } from "../src.ts/tor";
import { encode, decode } from "it-length-prefixed";
import { pipe } from "it-pipe";
import { toString } from "uint8arrays";

describe("tor", () => {
  let registry: Registry,
    proxies: Proxy[] = [],
    router: Router,
    router2: Router;

  before(async () => {
    registry = new Registry();
    await registry.run();
    Array.from(new Array(5)).map(() =>
      proxies.push(new Proxy(registry._libp2p.getMultiaddrs()))
    );
    router = new Router(registry._libp2p.getMultiaddrs());
    router2 = new Router(registry._libp2p.getMultiaddrs());
    await proxies.reduce(async (_, proxy) => {
      await proxy.run();
    }, Promise.resolve());
    await router.run({
      addresses: {
        listen: ["/ip4/127.0.0.1/tcp/0"],
      },
    });
    await router2.run({ addresses: { listen: ["/ip4/127.0.0.1/tcp/0"] } });
  });

  it("registry: should give the correct pubkey for the correct relay", async () => {
    const proxy = proxies[0];

    const pubKey = router.proxies.filter(
      (d) => d.id == proxy._libp2p.peerId.toString()
    )[0].publicKey;
    expect(equals(pubKey.marshal(), proxy.key())).to.equal(true);
  });

  it("extend: should perform a handshake with relays", async () => {
    await router.build(3);
  });
  it("begin: should begin the data relay", async () => {
    await router.build(3);
    await router.begin(proxies[4]._libp2p.getMultiaddrs()[0]);
  });

  it("rendezvous: should test rendezvous points", async () => {
    await router2.advertise();
    await router.rendezvous(router2.advertiseKey.public.marshal());
    await router2.waitForResponseOnChannel("rendezvous/test");
  });
});
