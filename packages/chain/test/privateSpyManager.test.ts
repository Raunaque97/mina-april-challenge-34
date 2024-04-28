import { Character, CircuitString, PrivateKey, PublicKey } from "o1js";
import {
  AgentData,
  MessageValidityProgram,
  PrivateSpyManager,
} from "../src/privateSpyManager";
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

describe("privateSpyManager", () => {
  let appChain: TestingAppChain<
    { Balances: typeof Balances } & {
      Balances: typeof Balances;
      PrivateSpyManager: typeof PrivateSpyManager;
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
      PrivateSpyManager,
    });
    spyMasterPrivateKey = PrivateKey.random();
    spyMaster = spyMasterPrivateKey.toPublicKey();
    appChain.configurePartial({
      Runtime: {
        Balances: {},
        PrivateSpyManager: {
          spyMaster,
        },
      },
    });
    await appChain.start();
    await MessageValidityProgram.compile();
  }, 120 * 1000);

  it(
    "should be able to add a valid message",
    async () => {
      const spyManager = appChain.runtime.resolve("PrivateSpyManager");
      const agentAkey = PrivateKey.random();
      const agentA = agentAkey.toPublicKey();
      const securityCode = CircuitString.fromCharacters(
        "AA".split("").map(Character.fromString)
      );
      // Spy Master adds an agent
      await addAgent(spyManager, agentA, securityCode);

      const agentDataB4 =
        (await appChain.query.runtime.PrivateSpyManager.records.get(
          agentA
        )) as AgentData;
      expect(
        agentDataB4?.lastMessageNumber.toBigInt().toString()
      ).toStrictEqual("0");
      expect(agentDataB4?.securityCodeHash.toBigInt().toString()).toStrictEqual(
        securityCode.hash().toBigInt().toString()
      );

      // Agent AA sends a message
      const message = CircuitString.fromCharacters(
        "BB_IS_RAT :)".split("").map(Character.fromString)
      );
      const proof = await MessageValidityProgram.generate(
        spyMaster,
        message,
        securityCode
      );

      appChain.setSigner(agentAkey);
      let txn = await appChain.transaction(agentA, () => {
        spyManager.addMessage(UInt64.from(99), proof);
      });
      await txn.sign();
      await txn.send();

      let block = await appChain.produceBlock();
      expect(
        block?.transactions[0].status.toBoolean(),
        block?.transactions[0].statusMessage
      ).toBe(true);

      const agentDataAfter =
        (await appChain.query.runtime.PrivateSpyManager.records.get(
          agentA
        )) as AgentData;
      expect(
        agentDataAfter?.lastMessageNumber.toBigInt().toString()
      ).toStrictEqual("99");
      expect(
        agentDataAfter.message.decrypt(spyMasterPrivateKey).toString()
      ).toStrictEqual("BB_IS_RAT :)");
    },
    2 * 60 * 1000
  );

  it(
    "should fail if security code is wrong",
    async () => {
      const spyManager = appChain.runtime.resolve("PrivateSpyManager");
      const agentAkey = PrivateKey.random();
      const agentA = agentAkey.toPublicKey();
      const securityCode = CircuitString.fromCharacters(
        "AA".split("").map(Character.fromString)
      );
      // Spy Master adds an agent
      await addAgent(spyManager, agentA, securityCode);
      // Agent AA sends a message but spy master did not add any agent
      appChain.setSigner(agentAkey);
      const message = CircuitString.fromCharacters(
        "BB_IS_RAT :)".split("").map(Character.fromString)
      );
      const wrongSecurityCode = CircuitString.fromCharacters(
        "A0".split("").map(Character.fromString)
      );
      const proof = await MessageValidityProgram.generate(
        spyMaster,
        message,
        wrongSecurityCode
      );
      let txn = await appChain.transaction(agentA, () => {
        spyManager.addMessage(UInt64.from(99), proof);
      });
      await txn.sign();
      await txn.send();
      let block = await appChain.produceBlock();
      expect(block?.transactions[0].status.toBoolean()).toBe(false);
      expect(block?.transactions[0].statusMessage).toBe(
        "Security Code Hash does not match"
      );
    },
    2 * 60 * 1000
  );

  async function addAgent(
    spyManager: PrivateSpyManager,
    agentA: PublicKey,
    securityCode: CircuitString
  ) {
    // Spy Master adds an agent
    appChain.setSigner(spyMasterPrivateKey);
    let txn = await appChain.transaction(spyMaster, () => {
      spyManager.addAgent(agentA, securityCode.hash());
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
