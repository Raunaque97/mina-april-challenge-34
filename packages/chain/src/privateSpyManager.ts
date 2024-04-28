import {
  runtimeModule,
  state,
  runtimeMethod,
  RuntimeModule,
} from "@proto-kit/module";
import { StateMap, assert } from "@proto-kit/protocol";
import { UInt64 } from "@proto-kit/library";
import {
  Character,
  CircuitString,
  Field,
  Experimental,
  PublicKey,
  Struct,
} from "o1js";

export class AgentData extends Struct({
  lastMessageNumber: UInt64,
  message: CircuitString,
  securityCodeHash: Field,
}) {
  static from(
    lastMessageNumber: UInt64,
    message: CircuitString,
    securityCodeHash: Field
  ): AgentData {
    return new AgentData({ lastMessageNumber, message, securityCodeHash });
  }
}

function checkCircuitStringLength(
  circuitString: CircuitString,
  length: number
) {
  // assert first `length` characters are not null Character
  for (let i = 0; i < length; i++) {
    circuitString.values[i].isNull().assertFalse("String is too short");
  }
  //assert all characters after first `length` characters are null Character
  for (let i = length; i < CircuitString.maxLength; i++) {
    circuitString.values[i].isNull().assertTrue("String is too long");
  }
}

export const MessageValidityProgram = Experimental.ZkProgram({
  publicInput: CircuitString,
  publicOutput: Field,
  methods: {
    generate: {
      privateInputs: [CircuitString],
      method(message: CircuitString, securityCode: CircuitString) {
        // check message length
        checkCircuitStringLength(message, 12);
        // check security code
        checkCircuitStringLength(securityCode, 2);
        // return hash of securityCode
        return securityCode.hash();
      },
    },
  },
});
export class MessageValidityProgramProof extends Experimental.ZkProgram.Proof(
  MessageValidityProgram
) {}

interface MessagesConfig {
  spyMaster: PublicKey;
}
@runtimeModule()
export class PrivateSpyManager extends RuntimeModule<MessagesConfig> {
  @state() public records = StateMap.from<PublicKey, AgentData>(
    PublicKey,
    AgentData
  );

  @runtimeMethod()
  public addAgent(agentID: PublicKey, securityCodeHash: Field): void {
    assert(
      this.transaction.sender.value.equals(this.config.spyMaster),
      "Only the Spy Master can add agents"
    );
    assert(this.records.get(agentID).isSome.not(), "Agent already exists");
    const agentData = AgentData.from(
      UInt64.zero,
      CircuitString.fromCharacters(
        new Array(12).fill(Character.fromString("_"))
      ),
      securityCodeHash
    );
    this.records.set(agentID, agentData);
  }

  @runtimeMethod()
  public addMessage(
    messageNumber: UInt64,
    messageValidityProof: MessageValidityProgramProof
  ): void {
    const agentID = this.transaction.sender.value;
    messageValidityProof.verify();
    assert(this.records.get(agentID).isSome, "Agent does not exist");
    const agentData = this.records.get(agentID).value;
    assert(
      messageNumber.greaterThan(agentData.lastMessageNumber),
      "Message number is not greater than last message number"
    );
    assert(
      messageValidityProof.publicOutput.equals(agentData.securityCodeHash),
      "Security Code Hash does not match"
    );
    // update the agent Data
    this.records.set(
      agentID,
      new AgentData({
        lastMessageNumber: messageNumber,
        message: messageValidityProof.publicInput,
        securityCodeHash: agentData.securityCodeHash,
      })
    );
  }
}
