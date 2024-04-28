import {
  runtimeModule,
  state,
  runtimeMethod,
  RuntimeModule,
} from "@proto-kit/module";
import { StateMap, assert } from "@proto-kit/protocol";
import { UInt64 } from "@proto-kit/library";
import { Character, CircuitString, Provable, PublicKey, Struct } from "o1js";

export class AgentData extends Struct({
  lastMessageNumber: UInt64,
  message: CircuitString,
  securityCode: CircuitString,
}) {
  static from(
    lastMessageNumber: UInt64,
    message: CircuitString,
    securityCode: CircuitString
  ): AgentData {
    return new AgentData({ lastMessageNumber, message, securityCode });
  }
}

interface MessagesConfig {
  spyMaster: PublicKey;
}

/**
 * checks if circuitString is of length `length`
 */
function checkCircuitStringLength(
  circuitString: CircuitString,
  length: number
) {
  // assert first `length` characters are not null Character
  for (let i = 0; i < length; i++) {
    assert(circuitString.values[i].isNull().not(), "String is too short");
  }
  //assert all characters after first `length` characters are null Character
  for (let i = length; i < CircuitString.maxLength; i++) {
    assert(circuitString.values[i].isNull(), "String is too long");
  }
}

@runtimeModule()
export class SpyManager extends RuntimeModule<MessagesConfig> {
  @state() public records = StateMap.from<PublicKey, AgentData>(
    PublicKey,
    AgentData
  );

  @runtimeMethod()
  public addAgent(agentID: PublicKey, securityCode: CircuitString): void {
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
      securityCode
    );
    this.records.set(agentID, agentData);
  }

  @runtimeMethod()
  public addMessage(
    message: CircuitString,
    messageNumber: UInt64,
    securityCode: CircuitString
  ): void {
    const agentID = this.transaction.sender.value;
    assert(this.records.get(agentID).isSome, "Agent does not exist");
    const agentData = this.records.get(agentID).value;
    assert(
      messageNumber.greaterThan(agentData.lastMessageNumber),
      "Message number is not greater than last message number"
    );
    assert(
      securityCode.equals(agentData.securityCode),
      "Security Code does not match"
    );
    checkCircuitStringLength(message, 12);
    checkCircuitStringLength(securityCode, 2);
    // update the agent Data
    this.records.set(
      agentID,
      new AgentData({
        lastMessageNumber: messageNumber,
        message: message,
        securityCode: securityCode,
      })
    );
  }
}
