import {
  Character,
  CircuitString,
  PrivateKey,
  Provable,
  PublicKey,
  Struct,
} from "o1js";
import { AgentData, SpyManager } from "../src/spyManager";
import {
  BlockStorageNetworkStateModule,
  InMemorySigner,
  InMemoryTransactionSender,
  StateServiceQueryModule,
  TestingAppChain,
} from "@proto-kit/sdk";
import { log } from "@proto-kit/common";
import { Balances, UInt64 } from "@proto-kit/library";
import { MandatoryProtocolModulesRecord } from "@proto-kit/protocol";
import {
  InMemoryDatabase,
  PrivateMempool,
  LocalTaskWorkerModule,
  NoopBaseLayer,
  BlockProducerModule,
  UnprovenProducerModule,
  ManualBlockTrigger,
  LocalTaskQueue,
  SettlementModule,
} from "@proto-kit/sequencer";

log.setLevel("ERROR");

describe("spyManager", () => {
  let appChain: TestingAppChain<
    { Balances: typeof Balances } & {
      Balances: typeof Balances;
      SpyManager: typeof SpyManager;
    },
    MandatoryProtocolModulesRecord & { TransactionFee: any },
    {
      Database: typeof InMemoryDatabase;
      Mempool: typeof PrivateMempool;
      LocalTaskWorkerModule: typeof LocalTaskWorkerModule;
      BaseLayer: typeof NoopBaseLayer;
      BlockProducerModule: typeof BlockProducerModule;
      UnprovenProducerModule: typeof UnprovenProducerModule;
      BlockTrigger: typeof ManualBlockTrigger;
      TaskQueue: typeof LocalTaskQueue;
      SettlementModule: typeof SettlementModule;
    },
    {
      Signer: typeof InMemorySigner;
      TransactionSender: typeof InMemoryTransactionSender;
      QueryTransportModule: typeof StateServiceQueryModule;
      NetworkStateTransportModule: typeof BlockStorageNetworkStateModule;
    }
  >;
  let spyMasterPrivateKey: PrivateKey;
  let spyMaster: PublicKey;
  beforeAll(async () => {
    appChain = TestingAppChain.fromRuntime({
      Balances,
      SpyManager,
    });
    spyMasterPrivateKey = PrivateKey.random();
    spyMaster = spyMasterPrivateKey.toPublicKey();
    appChain.configurePartial({
      Runtime: {
        Balances: {},
        SpyManager: {
          spyMaster,
        },
      },
    });
    await appChain.start();
  });

  it("should be able to add a valid message", async () => {
    const spyManager = appChain.runtime.resolve("SpyManager");
    const agentAkey = PrivateKey.random();
    const agentA = agentAkey.toPublicKey();
    const securityCode = CircuitString.fromCharacters(
      "AA".split("").map(Character.fromString)
    );
    // Spy Master adds an agent
    await addAgent(spyManager, agentA, securityCode);

    const agentDataB4 = (await appChain.query.runtime.SpyManager.records.get(
      agentA
    )) as AgentData;
    expect(agentDataB4?.lastMessageNumber.toBigInt().toString()).toStrictEqual(
      "0"
    );

    // Agent AA sends a message
    appChain.setSigner(agentAkey);
    const message = CircuitString.fromCharacters(
      "BB_IS_RAT :)".split("").map(Character.fromString)
    );
    let txn = await appChain.transaction(agentA, () => {
      spyManager.addMessage(message, UInt64.from(99), securityCode);
    });
    await txn.sign();
    await txn.send();

    let block = await appChain.produceBlock();
    expect(
      block?.transactions[0].status.toBoolean(),
      block?.transactions[0].statusMessage
    ).toBe(true);

    const agentDataAfter = (await appChain.query.runtime.SpyManager.records.get(
      agentA
    )) as AgentData;
    expect(
      agentDataAfter?.lastMessageNumber.toBigInt().toString()
    ).toStrictEqual("99");
    expect(agentDataAfter?.message).toStrictEqual(message);
  });

  it("should fail if agent does not exist", async () => {
    const spyManager = appChain.runtime.resolve("SpyManager");
    const agentAkey = PrivateKey.random();
    const agentA = agentAkey.toPublicKey();
    const securityCode = CircuitString.fromCharacters(
      "AA".split("").map(Character.fromString)
    );
    // Agent AA sends a message but spy master did not add any agent
    appChain.setSigner(agentAkey);
    const message = CircuitString.fromCharacters(
      "BB_IS_RAT :)".split("").map(Character.fromString)
    );
    let txn = await appChain.transaction(agentA, () => {
      spyManager.addMessage(message, UInt64.from(99), securityCode);
    });
    await txn.sign();
    await txn.send();

    let block = await appChain.produceBlock();
    expect(block?.transactions[0].status.toBoolean()).toBe(false);
    expect(block?.transactions[0].statusMessage).toBe("Agent does not exist");
  });

  it("should fail if security code does not match", async () => {
    const spyManager = appChain.runtime.resolve("SpyManager");
    const agentAkey = PrivateKey.random();
    const agentA = agentAkey.toPublicKey();
    const securityCode = CircuitString.fromCharacters(
      "AA".split("").map(Character.fromString)
    );
    // Spy Master adds an agent
    await addAgent(spyManager, agentA, securityCode);

    // Agent AA sends a message with wrong security code
    const wrongSecurityCode = CircuitString.fromCharacters(
      "A0".split("").map(Character.fromString)
    );
    appChain.setSigner(agentAkey);
    const message = CircuitString.fromCharacters(
      "BB_IS_RAT :)".split("").map(Character.fromString)
    );
    let txn = await appChain.transaction(agentA, () => {
      spyManager.addMessage(message, UInt64.from(2), wrongSecurityCode);
    });
    await txn.sign();
    await txn.send();

    let block = await appChain.produceBlock();
    expect(block?.transactions[0].status.toBoolean()).toBe(false);
    expect(block?.transactions[0].statusMessage).toBe(
      "Security Code does not match"
    );
  });

  it("should fail if message number is not greater than last message number", async () => {
    const spyManager = appChain.runtime.resolve("SpyManager");
    const agentAkey = PrivateKey.random();
    const agentA = agentAkey.toPublicKey();
    const securityCode = CircuitString.fromCharacters(
      "AA".split("").map(Character.fromString)
    );
    // Spy Master adds an agent
    await addAgent(spyManager, agentA, securityCode);

    // Agent AA sends a message with message number not greater than last message number
    appChain.setSigner(agentAkey);
    const message = CircuitString.fromCharacters(
      "BB_IS_RAT :)".split("").map(Character.fromString)
    );
    let txn = await appChain.transaction(agentA, () => {
      spyManager.addMessage(message, UInt64.from(0), securityCode);
    });
    await txn.sign();
    await txn.send();

    let block = await appChain.produceBlock();
    expect(block?.transactions[0].status.toBoolean()).toBe(false);
    expect(block?.transactions[0].statusMessage).toBe(
      "Message number is not greater than last message number"
    );
  });

  it("should fail if message length is not 12", async () => {
    const spyManager = appChain.runtime.resolve("SpyManager");
    const agentAkey = PrivateKey.random();
    const agentA = agentAkey.toPublicKey();
    const securityCode = CircuitString.fromCharacters(
      "AA".split("").map(Character.fromString)
    );
    // Spy Master adds an agent
    await addAgent(spyManager, agentA, securityCode);

    // Agent AA sends a message with invalid length
    appChain.setSigner(agentAkey);
    const message = CircuitString.fromCharacters(
      "BB_IS_RAT".split("").map(Character.fromString)
    );
    let txn = await appChain.transaction(agentA, () => {
      spyManager.addMessage(message, UInt64.from(2), securityCode);
    });
    await txn.sign();
    await txn.send();

    let block = await appChain.produceBlock();
    expect(block?.transactions[0].status.toBoolean()).toBe(false);
    expect(block?.transactions[0].statusMessage).toBe("String is too short");
  });

  async function addAgent(
    spyManager: SpyManager,
    agentA: PublicKey,
    securityCode: CircuitString
  ) {
    // Spy Master adds an agent
    appChain.setSigner(spyMasterPrivateKey);
    let txn = await appChain.transaction(spyMaster, () => {
      spyManager.addAgent(agentA, securityCode);
    });
    await txn.sign();
    await txn.send();
    let block = await appChain.produceBlock();
    expect(
      block?.transactions[0].status.toBoolean(),
      block?.transactions[0].statusMessage
    ).toBe(true);
  }
});
