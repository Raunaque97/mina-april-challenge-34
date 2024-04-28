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
  Group,
  Encryption,
  PrivateKey,
  Provable,
} from "o1js";

export class EncryptedMessage extends Struct({
  publicKey: Group,
  cipherText: Provable.Array(Field, 129),
}) {
  static EMPTY = new EncryptedMessage({
    publicKey: Group.zero,
    cipherText: Array.from({ length: 129 }, () => Field(0)),
  });
  static from(message: CircuitString, publicKey: PublicKey) {
    return new EncryptedMessage(
      Encryption.encrypt(message.toFields(), publicKey)
    );
  }

  public decrypt(privateKey: PrivateKey): CircuitString {
    const copy = {
      publicKey: this.publicKey,
      cipherText: [...this.cipherText],
    };
    return CircuitString.fromCharacters(
      Encryption.decrypt(copy, privateKey).map((f) => Character.fromFields([f]))
    );
  }
}

export class AgentData extends Struct({
  lastMessageNumber: UInt64,
  message: EncryptedMessage,
  securityCodeHash: Field,
}) {
  static from(
    lastMessageNumber: UInt64,
    message: EncryptedMessage,
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

export class MessageValidityProgramOutput extends Struct({
  securityCodeHash: Field,
  encryptedMessage: EncryptedMessage,
}) {}

export const MessageValidityProgram = Experimental.ZkProgram({
  publicInput: PublicKey,
  publicOutput: MessageValidityProgramOutput,
  methods: {
    generate: {
      privateInputs: [CircuitString, CircuitString],
      method(
        messageRecipient: PublicKey,
        message: CircuitString,
        securityCode: CircuitString
      ) {
        // check message length
        checkCircuitStringLength(message, 12);
        // check security code
        checkCircuitStringLength(securityCode, 2);
        // return hash of securityCode
        return {
          encryptedMessage: EncryptedMessage.from(message, messageRecipient),
          securityCodeHash: securityCode.hash(),
        };
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
      EncryptedMessage.EMPTY,
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
      messageValidityProof.publicInput.equals(this.config.spyMaster),
      "Not encrypted with Spy Master's public key"
    );
    assert(
      messageNumber.greaterThan(agentData.lastMessageNumber),
      "Message number is not greater than last message number"
    );
    assert(
      messageValidityProof.publicOutput.securityCodeHash.equals(
        agentData.securityCodeHash
      ),
      "Security Code Hash does not match"
    );
    // update the agent Data
    this.records.set(
      agentID,
      new AgentData({
        lastMessageNumber: messageNumber,
        message: messageValidityProof.publicOutput.encryptedMessage,
        securityCodeHash: agentData.securityCodeHash,
      })
    );
  }
}
