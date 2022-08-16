require "./spec_helper"

module Homekit::TLV
  describe Atom do
    it "should parse a separator" do
      io = IO::Memory.new(Bytes[0xff, 0])
      msg = io.read_bytes(Atom)
      msg.separator?.should be_true
      msg.ignore?.should be_true
      msg.acknowledgment?.should be_false
      msg.type.should eq TLV::Type::Separator
      msg.known_type?.should eq TLV::Type::Separator
    end

    it "should parse an aknowledgement" do
      io = IO::Memory.new(Bytes[12, 0])
      msg = io.read_bytes(Atom)
      msg.separator?.should be_false
      msg.ignore?.should be_false
      msg.acknowledgment?.should be_true
      msg.type.should eq TLV::Type::FragmentData
      msg.known_type?.should eq TLV::Type::FragmentData
    end

    it "should parse an unknown tlv type" do
      io = IO::Memory.new(Bytes[250, 2, 3, 4])
      msg = io.read_bytes(Atom)
      msg.separator?.should be_false
      msg.ignore?.should be_true
      msg.acknowledgment?.should be_false
      msg.known_type?.should be_nil
    end

    it "should parse an integer" do
      io = IO::Memory.new(Bytes[4, 2, 0, 4])
      msg = io.read_bytes(Atom)
      msg.separator?.should be_false
      msg.ignore?.should be_false
      msg.acknowledgment?.should be_false
      msg.known_type?.should eq TLV::Type::Proof

      msg.to_u64.should eq 1024_u64
      msg.to_u32.should eq 1024_u32
      msg.to_u16.should eq 1024_u16
      msg.to_i64.should eq 1024_i64
      msg.to_i32.should eq 1024_i32
      msg.to_i16.should eq 1024_i16
    end

    it "should parse a small float" do
      io = IO::Memory.new(Bytes[5, 4, 37, 6, 73, 64])
      msg = io.read_bytes(Atom)
      msg.separator?.should be_false
      msg.ignore?.should be_false
      msg.acknowledgment?.should be_false
      msg.known_type?.should eq TLV::Type::EncryptedData

      msg.to_f32.should eq 3.141_f32
    end

    it "should parse a large float" do
      io = IO::Memory.new(8)
      io.write Bytes[5, 8]
      io.write_bytes 45.123_f64, IO::ByteFormat::LittleEndian
      io.rewind
      msg = io.read_bytes(Atom)
      msg.separator?.should be_false
      msg.ignore?.should be_false
      msg.acknowledgment?.should be_false
      msg.known_type?.should eq TLV::Type::EncryptedData

      msg.to_f.should eq 45.123_f64
    end

    it "should parse a string" do
      message = "Hello 🌍"
      io = IO::Memory.new
      io.write Bytes[1, message.bytesize]
      io.write message.to_slice
      io.rewind
      msg = io.read_bytes(Atom)
      msg.separator?.should be_false
      msg.ignore?.should be_false
      msg.acknowledgment?.should be_false
      msg.known_type?.should eq TLV::Type::Identifier

      msg.identifier.should eq message
    end
  end

  describe TLV do
    it "should parse a multipart message" do
      message = "t" * 258
      part1 = "t" * 255
      part2 = "ttt"
      io = IO::Memory.new
      io.write Bytes[1, part1.bytesize]
      io.write part1.to_slice
      io.write Bytes[1, part2.bytesize]
      io.write part2.to_slice

      atoms = TLV.parse(io.to_slice)
      atoms.size.should eq(1)
      atoms.first.to_s.should eq(message)
    end

    it "should encode a multipart atom" do
      message = "t" * 258
      part1 = "t" * 255
      part2 = "ttt"
      io = IO::Memory.new
      io.write Bytes[1, part1.bytesize]
      io.write part1.to_slice
      io.write Bytes[1, part2.bytesize]
      io.write part2.to_slice

      atom = Atom.new
      atom.type_id = 1
      atom.raw_data = message.to_slice
      encoded = TLV.encode(atom)

      encoded.to_slice.should eq(io.to_slice)
    end

    it "should separate atoms of the same type" do
      message = "t" * 255
      io = IO::Memory.new
      io.write Bytes[1, message.bytesize]
      io.write message.to_slice
      io.write Bytes[0xFF, 0] # the separator
      io.write Bytes[1, message.bytesize]
      io.write message.to_slice

      atom = Atom.new
      atom.type_id = 1
      atom.raw_data = message.to_slice

      encoded = TLV.encode({atom, atom})
      encoded.to_slice.should eq(io.to_slice)
    end
  end
end
