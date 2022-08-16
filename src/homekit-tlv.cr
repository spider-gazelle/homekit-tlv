module Homekit::TLV
  {% begin %}
    VERSION = {{ `shards version "#{__DIR__}"`.chomp.stringify.downcase }}
  {% end %}

  enum PairError : UInt8
    Unknown        = 1
    Authentication = 2
    Backoff        = 3
    MaxPeers       = 4
    MaxTries       = 5
    Unavailable    = 6
    Busy           = 7
  end

  enum Type : UInt8
    PairingMethod    =    0 # integer (see enum below)
    Identifier       =    1 # utf8 string
    Salt             =    2 # bytes (16+ bytes of random salt)
    PublicKey        =    3 # bytes (Curve25519, SRP public key, or signed Ed25519 key)    )
    Proof            =    4 # bytes (Ed25519 or SRP proof)
    EncryptedData    =    5 # bytes (Encrypted data with auth tag at end, this could be any data type)
    State            =    6 # integer (1=M1, 2=M2, etc, PairVerifyStep enum below)
    Error            =    7 # integer (see PairError enum above)
    RetryDelay       =    8 # integer (Seconds to delay until retrying a setup code)
    Certificate      =    9 # bytes (X.509 Certificate)
    Signature        =   10 # bytes (Ed25519)
    Permissions      =   11 # integer (0 == user, 1 == admin)
    FragmentData     =   12 # bytes (length 0 == ACK)
    FragmentLast     =   13 # bytes
    PairingTypeFlags =   14 # integer
    Separator        = 0xFF # null
  end

  enum PairingMethod : UInt8
    PairSetup         = 0
    PairSetupWithAuth = 1
    PairVerify        = 2
    AddPairing        = 3
    RemovePairing     = 4
    ListPairings      = 5
  end

  enum PairSetupStep
    Waiting = 0

    # M1: iOS Device -> Accessory -- `SRP Start Request'
    StartRequest = 1

    # M2: Accessory -> iOS Device -- `SRP Start Response'
    StartResponse = 2

    # M3: iOS Device -> Accessory -- `SRP Verify Request'
    VerifyRequest = 3

    # M4: Accessory -> iOS Device -- `SRP Verify Response'
    VerifyResponse = 4

    # M5: iOS Device -> Accessory -- `Exchange Request'
    KeyExchangeRequest = 5

    # M6: Accessory -> iOS Device -- `Exchange Response'
    KeyExchangeResponse = 6
  end

  enum PairVerifyStep
    Waiting = 0

    # M1: iOS Device -> Accessory -- `Verify Start Request'
    StartRequest = 1

    # M2: Accessory -> iOS Device -- `Verify Start Response'
    StartResponse = 2

    # M3: iOS Device -> Accessory -- `Verify Finish Request'
    FinishRequest = 3

    # M4: Accessory -> iOS Device -- `Verify Finish Response'
    FinishResponse = 4
  end

  enum Permissions
    User
    Admin
  end

  def self.parse(bytes : Bytes) : Array(Atom)
    io = IO::Memory.new(bytes)
    atoms = [] of Atom
    current_atom = nil

    loop do
      # check for end of data
      break if io.pos == bytes.size
      next_atom = io.read_bytes(Atom)

      # Is this a new entry or is it the next bit of a fragment
      if current_atom && current_atom.type_id == next_atom.type_id
        current_atom.next_fragment = next_atom
      else
        # Don't include the seperators in the list
        atoms << next_atom unless next_atom.separator?
      end

      # If the length of the atom is 255 then the next atom might be a continuation
      if next_atom.length == 0xFF_u8
        current_atom = next_atom
      else
        current_atom = nil
      end
    end
    atoms
  end

  def self.encode(atom : Atom, io = IO::Memory.new) : IO
    type = atom.type_id
    data = atom.data

    if data.size > 0xFF
      starting = 0
      ending = 0xFF

      loop do
        # multi-part parts must use the max size available
        part = data[starting...ending]
        io.write_byte type
        io.write_byte part.size.to_u8
        io.write part

        # check if we wrote the final part
        break if ending >= data.size
        starting += 0xFF
        ending += 0xFF
        ending = data.size if ending > data.size
      end
    else
      io.write_byte type
      io.write_byte data.size.to_u8
      io.write data
    end

    io
  end

  SEPARATOR = Atom.new
  SEPARATOR.type_id = 0xFF_u8

  def self.encode(atoms : Enumerable(Atom), io = IO::Memory.new) : IO
    previous_type = nil
    atoms.each do |atom|
      # A seperator is required between atoms of the same type following one another
      encode(SEPARATOR, io) if previous_type == atom.type_id
      encode(atom, io)
      previous_type = atom.type_id
    end
    io
  end
end

require "./homekit-tlv/*"
