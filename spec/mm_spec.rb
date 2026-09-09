# frozen_string_literal: true

require 'elftools/segments/load_segment'
require 'elftools/structs'

require 'patchelf/mm'

describe PatchELF::MM do
  def make_load(off, filesz, vaddr, memsz, perm)
    header = ELFTools::Structs::ELF_Phdr[64].new(endian: :little)
    header.p_offset = off
    header.p_filesz = filesz
    header.p_vaddr = vaddr
    header.p_memsz = memsz
    header.p_flags = perm_to_flag(perm)
    ELFTools::Segments::LoadSegment.new(header, nil)
  end

  def perm_to_flag(perm)
    f = 0
    f |= 1 if perm.include?('x')
    f |= 2 if perm.include?('w')
    f |= 4 if perm.include?('r')
    f
  end

  def test_dispatch(request_size, loads, e_machine: ELFTools::Constants::EM_X86_64, &block)
    elf = {}
    allow(elf).to receive(:segments_by_type).and_return loads
    obj = allow(elf).to receive(:each_segments)
    loads.each { |seg| obj.and_yield(seg) }
    allow(elf).to receive(:each_sections) {} # do nothing
    ehdr = ELFTools::Structs::ELF_Ehdr.new(endian: :little)
    ehdr.elf_class = 64
    ehdr.e_machine = e_machine
    allow(elf).to receive(:header).and_return ehdr

    mm = described_class.new(elf)
    block ||= ->(_, _) {}
    mm.malloc(request_size, &block)
    mm.dispatch!
  end

  # Normal ELF, with R-X and RW- LOADs.
  describe 'normal case' do
    it 'fgap' do
      loads = [make_load(0, 0x666, 0x1000, 0x666, 'rx'), make_load(0x668, 8, 0x2668, 8, 'rw')]
      called = 0
      test_dispatch(2, loads) do |off, vaddr|
        expect(off).to be 0x666
        expect(vaddr).to be 0x2666
        called += 1
      end
      expect(loads[1].file_head).to be 0x666
      expect(called).to be 1
    end

    it 'mgap' do
      loads = [make_load(0, 0x666, 0x1000, 0x666, 'rx'), make_load(0x668, 8, 0x3668, 8, 'rw')]
      called = 0
      test_dispatch(0x100, loads) do |off, vaddr|
        expect(off).to be 0x668
        expect(vaddr).to be 0x2668
        called += 1
      end
      expect(loads[1].file_head).to be 0x668
      expect(called).to be 1
    end

    it 'new_load_method' do
      loads = [make_load(0, 0xa2c, 0, 0xa2c, 'rx'), make_load(0xeb0, 0x158, 0x1eb0, 0x15c, 'rw')]
      expect { test_dispatch(0x2000, loads) }.to raise_error(NotImplementedError)
    end
  end

  describe 'architecture-specific page sizes' do
    it 'mgap with AArch64 (64KB page size)' do
      loads = [
        make_load(0, 0xf800, 0x10000, 0xf800, 'rx'),
        make_load(0x10000, 0x1000, 0x30000, 0x1000, 'rw')
      ]
      loads.each { |seg| seg.header.p_align = 0x10000 }
      called = 0
      test_dispatch(0x1000, loads, e_machine: ELFTools::Constants::EM_AARCH64) do |off, vaddr|
        expect(off).to be 0x10000
        expect(vaddr).to be 0x20000
        called += 1
      end
      expect(loads[1].file_head).to be 0x10000
      expect(PatchELF::Helper.aligndown(loads[1].mem_head, 0x10000))
        .to be >= PatchELF::Helper.alignup(loads[0].mem_tail, 0x10000)
      expect(called).to be 1
    end

    [0x20000, 0x22000].each do |vaddr|
      it "rejects a rounded forward extension that overlaps a mapped page at #{vaddr.to_s(16)}" do
        loads = [
          make_load(0, 0x1800, 0x10000, 0x1800, 'rx'),
          make_load(0x2000, 0x1000, vaddr, 0x1000, 'rw')
        ]
        loads.each { |seg| seg.header.p_align = 0x1000 }
        headers = loads.map { |seg| seg.header.to_binary_s }
        callback = double('callback')
        expect(callback).not_to receive(:call)

        expect do
          test_dispatch(0x1000, loads, e_machine: ELFTools::Constants::EM_AARCH64) { |*args| callback.call(*args) }
        end.to raise_error(NotImplementedError)
        expect(loads.map { |seg| seg.header.to_binary_s }).to eq headers
      end
    end

    it 'allows backward growth when only the unrounded request fits' do
      loads = [
        make_load(0, 0x1800, 0x10000, 0x1800, 'rw'),
        make_load(0x2000, 0x1000, 0x20000, 0x1000, 'r')
      ]
      loads.each { |seg| seg.header.p_align = 0x1000 }
      test_dispatch(0x1000, loads, e_machine: ELFTools::Constants::EM_AARCH64) do |off, vaddr|
        expect(off).to be 0x1800
        expect(vaddr).to be 0x11800
      end
      expect(loads[0].mem_tail).to be 0x12800
      expect(loads[1].file_head).to be 0x12000
    end

    it 'preserves congruent PT_LOAD alignment after shifting' do
      loads = [
        make_load(0, 0x1000, 0x10000, 0x1000, 'rx'),
        make_load(0x1800, 0x1000, 0x15800, 0x1000, 'rw')
      ]
      loads[1].header.p_align = 0x2000
      test_dispatch(0x2000, loads)
      expect(loads[1].header.p_align).to eq 0x2000
      expect(loads[1].header.p_vaddr % loads[1].header.p_align)
        .to eq(loads[1].header.p_offset % loads[1].header.p_align)
    end

    it 'repairs PT_LOAD alignment made incongruent by shifting' do
      loads = [
        make_load(0, 0x1000, 0x1000, 0x1000, 'rx'),
        make_load(0x1800, 0x1000, 0x3800, 0x1000, 'rw')
      ]
      loads[1].header.p_align = 0x2000
      test_dispatch(0x1000, loads)
      expect(loads[1].header.p_align).to eq 0x1000
      expect(loads[1].header.p_vaddr % loads[1].header.p_align)
        .to eq(loads[1].header.p_offset % loads[1].header.p_align)
    end
  end

  describe 'extend backwardly' do
    it 'uses forward growth when the previous LOAD has a BSS area' do
      loads = [
        make_load(0, 0x100, 0x1000, 0x200, 'rw'),
        make_load(0x200, 0x100, 0x3000, 0x100, 'rw')
      ]
      test_dispatch(0x20, loads) do |off, vaddr|
        expect(off).to be 0x1e0
        expect(vaddr).to be 0x2fe0
      end
      expect(loads[0].file_tail).to be 0x100
      expect(loads[0].mem_tail).to be 0x1200
      expect(loads[1].file_head).to be 0x1e0
    end

    it 'rejects a file gap when the virtual gap is too small' do
      loads = [
        make_load(0, 0x100, 0x1000, 0x200, 'rw'),
        make_load(0x200, 0x100, 0x1210, 0x100, 'rw')
      ]
      headers = loads.map { |seg| seg.header.to_binary_s }
      callback = double('callback')
      expect(callback).not_to receive(:call)

      expect do
        test_dispatch(0x20, loads) { |*args| callback.call(*args) }
      end.to raise_error(NotImplementedError)
      expect(loads.map { |seg| seg.header.to_binary_s }).to eq headers
    end

    it 'rejects backward growth into the next LOAD aligned page' do
      loads = [
        make_load(0, 0x800, 0x1000, 0x800, 'rw'),
        make_load(0x1200, 0x100, 0x2800, 0x100, 'r')
      ]
      headers = loads.map { |seg| seg.header.to_binary_s }
      callback = double('callback')
      expect(callback).not_to receive(:call)

      expect do
        test_dispatch(0x900, loads) { |*args| callback.call(*args) }
      end.to raise_error(NotImplementedError)
      expect(loads.map { |seg| seg.header.to_binary_s }).to eq headers
    end

    it 'rejects forward growth that enters the previous LOAD page' do
      loads = [
        make_load(0, 0x100, 0x1000, 0x1800, 'rw'),
        make_load(0x200, 0x100, 0x3000, 0x100, 'rw')
      ]
      headers = loads.map { |seg| seg.header.to_binary_s }
      callback = double('callback')
      expect(callback).not_to receive(:call)

      expect do
        test_dispatch(0x100, loads) { |*args| callback.call(*args) }
      end.to raise_error(NotImplementedError)
      expect(loads.map { |seg| seg.header.to_binary_s }).to eq headers
    end

    it 'fgap' do
      loads = [make_load(0, 0x666, 0x1000, 0x666, 'rwx'), make_load(0x668, 8, 0x2668, 8, 'rw')]
      called = 0
      test_dispatch(2, loads) do |off, vaddr|
        expect(off).to be 0x666
        expect(vaddr).to be 0x1666
        called += 1
      end
      expect(loads[0].file_tail).to be 0x668
      expect(loads[1].file_head).to be 0x668
      expect(called).to be 1
    end

    it 'mgap' do
      loads = [make_load(0, 0x666, 0x1000, 0x666, 'rw'), make_load(0x668, 8, 0x2668, 8, 'r')]
      called = 0
      test_dispatch(0x200, loads) do |off, vaddr|
        expect(off).to be 0x666
        expect(vaddr).to be 0x1666
        called += 1
      end
      expect(loads[0].file_tail).to be 0x866
      expect(loads[1].file_head).to be 0x1668
      expect(called).to be 1

      # We should be able to extend it again!
      # This time the fgap should be used
      test_dispatch(0x200, loads)
      expect(loads[0].file_tail).to be 0xa66
      expect(loads[1].file_head).to be 0x1668
    end

    it 'does not use an m-gap when the previous LOAD has a BSS area' do
      loads = [
        make_load(0, 0x100, 0x1000, 0x200, 'rw'),
        make_load(0x200, 0x100, 0x3000, 0x100, 'r')
      ]
      headers = loads.map { |seg| seg.header.to_binary_s }
      callback = double('callback')
      expect(callback).not_to receive(:call)

      expect do
        test_dispatch(0x200, loads) { |*args| callback.call(*args) }
      end.to raise_error(NotImplementedError)
      expect(loads.map { |seg| seg.header.to_binary_s }).to eq headers
    end

    it 'rejects an m-gap that fits the request but not the extension' do
      loads = [
        make_load(0, 0x100, 0x1000, 0x200, 'rw'),
        make_load(0x100, 0x100, 0x2e00, 0x100, 'rw')
      ]
      headers = loads.map { |seg| seg.header.to_binary_s }
      callback = double('callback')
      expect(callback).not_to receive(:call)

      expect do
        test_dispatch(0x800, loads) { |*args| callback.call(*args) }
      end.to raise_error(NotImplementedError)
      expect(loads.map { |seg| seg.header.to_binary_s }).to eq headers
    end

    it 'uses forward growth when the full m-gap extension fits' do
      loads = [
        make_load(0, 0x100, 0x1000, 0x200, 'rw'),
        make_load(0x100, 0x100, 0x4000, 0x100, 'rw')
      ]
      test_dispatch(0x200, loads) do |off, vaddr|
        expect(off).to be 0x100
        expect(vaddr).to be 0x3000
      end
      expect(loads[0].mem_tail).to be 0x1200
      expect(loads[1].mem_head).to be 0x3000
    end
  end

  describe 'abnormal ELF' do
    it 'no LOAD' do
      expect { test_dispatch(1, []) }.to raise_error(ArgumentError)
    end

    it 'out of order' do
      expect { test_dispatch(1, [make_load(1, 1, 1, 1, 'rw'), make_load(0, 0, 0, 0, 'rw')]) }
        .to raise_error(ArgumentError)
    end
  end
end
