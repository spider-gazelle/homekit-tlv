require "bindata"

module Homekit::TLV
  class Atom < BinData
    endian little

    # we don't use enum_field so we can ignore new types that we don't know of yet
    uint8 :type_id
    uint8 :length, value: ->{ raw_data.size.to_u8 }
    bytes :raw_data, length: ->{ length }

    # ================
    # Helper functions
    # ================

    property next_fragment : Atom? = nil

    getter? known_type : TLV::Type? { TLV::Type.from_value?(type_id) }
    getter type : TLV::Type { known_type?.not_nil! }
    getter? error : TLV::PairError? do
      if known_type?.try &.error?
        TLV::PairError.from_value(raw_data[0])
      end
    end

    def separator? : Bool
      !!known_type?.try(&.separator?)
    end

    def ignore? : Bool
      !known_type? || separator?
    end

    def acknowledgment? : Bool
      !!known_type?.try(&.fragment_data?) && length.zero?
    end

    def method
      TLV::Method.from_value(raw_data[0])
    end

    def permissions
      TLV::Permissions.from_value(raw_data[0])
    end

    def data
      if next_fragment
        io = IO::Memory.new
        io.write raw_data
        next_part = next_fragment
        loop do
          break unless next_part
          io.write next_part.raw_data
          next_part = next_part.next_fragment
        end
        io.to_slice
      else
        raw_data
      end
    end

    def to_s
      String.new(data)
    end

    def identifier
      to_s
    end

    def to_u64
      io = IO::Memory.new(Bytes.new(8, 0_u8))
      io.write(raw_data)
      io.rewind
      io.read_bytes(UInt64, IO::ByteFormat::LittleEndian)
    end

    def to_u32
      io = IO::Memory.new(Bytes.new(4, 0_u8))
      io.write(raw_data)
      io.rewind
      io.read_bytes(UInt32, IO::ByteFormat::LittleEndian)
    end

    def to_u16
      io = IO::Memory.new(Bytes.new(2, 0_u8))
      io.write(raw_data)
      io.rewind
      io.read_bytes(UInt16, IO::ByteFormat::LittleEndian)
    end

    def to_u8
      raw_data[0]
    end

    def to_i64
      io = IO::Memory.new(Bytes.new(8, 0_u8))
      io.write(raw_data)
      io.rewind
      io.read_bytes(Int64, IO::ByteFormat::LittleEndian)
    end

    def to_i32
      io = IO::Memory.new(Bytes.new(4, 0_u8))
      io.write(raw_data)
      io.rewind
      io.read_bytes(Int32, IO::ByteFormat::LittleEndian)
    end

    def to_i
      to_i32
    end

    def to_i16
      io = IO::Memory.new(Bytes.new(2, 0_u8))
      io.write(raw_data)
      io.rewind
      io.read_bytes(Int16, IO::ByteFormat::LittleEndian)
    end

    def to_i8
      io = IO::Memory.new(Bytes.new(1, 0_u8))
      io.write(raw_data)
      io.rewind
      io.read_bytes(Int8, IO::ByteFormat::LittleEndian)
    end

    def to_f32
      io = IO::Memory.new(4)
      io.write(raw_data)
      io.rewind
      io.read_bytes(Float32, IO::ByteFormat::LittleEndian)
    end

    def to_f64
      io = IO::Memory.new(8)
      io.write(raw_data)
      io.rewind
      io.read_bytes(Float64, IO::ByteFormat::LittleEndian)
    end

    def to_f
      to_f64
    end
  end
end
