using Dates
using Printf

export pcap_t, bpf_program, pcap_pkthdr,
       pcap_lookupdev, pcap_open_live, pcap_compile, pcap_setfilter, pcap_next_ex, pcap_inject

PCAP_ERRBUF_SIZE = 256
PCAP_NETMASK_UNKNOWN = 0xffffffff

mutable struct pcap_t
end

mutable struct bpf_insn
end

mutable struct bpf_program
    bpf_len::Cuint
    bf_insns::Ptr{bpf_insn}

    function bpf_program()
        new(0, 0)
    end
end

mutable struct pcap_pkthdr
    tv_sec::Clong
    tv_usec::Clong
    caplen::UInt32
    len::UInt32

    function pcap_pkthdr()
        new(0, 0, 0, 0)
    end
end

Base.show(io::IO, hdr::pcap_pkthdr) = print(io, hdr)
Base.print(io::IO, hdr::pcap_pkthdr) = print(io, @sprintf("(timestamp => %s, caplen => %u, len => %u)", Dates.unix2datetime(hdr.tv_sec + hdr.tv_usec / 1000000), hdr.caplen, hdr.len))

#----------
# lookup default device
#----------
function pcap_lookupdev()
    dev = ccall((:pcap_lookupdev, :libpcap),
                Ptr{UInt8},
                ())
    if dev == C_NULL
        throw(ErrorException("pcap_lookupdev: $(pcap_geterr(handle))"))
    else
        unsafe_string(dev)
    end
end # function pcap_lookupdev

#----------
# get libpcap error message text
#----------
function pcap_geterr(handle)
    errptr = ccall((:pcap_geterr, :libpcap),
                   Cstring,
                   (Ptr{pcap_t},),
                   handle)
    unsafe_string(errptr)
end # function pcap_geterr

#----------
# open a device for capturing
#----------
function pcap_open_live(device, snaplen, promisc, to_ms)
    errbuf = Vector{UInt8}(undef, PCAP_ERRBUF_SIZE)
    handle = ccall((:pcap_open_live, :libpcap),
                   Ptr{pcap_t},
                   (Cstring, Cint, Cint, Cint, Ref{UInt8}),
                   device, snaplen, promisc, to_ms, errbuf)
    if handle == C_NULL
        errbuf[end] = 0
        throw(ErrorException("pcap_open_live: $(unsafe_string(pointer(errbuf)))"))
    else
        handle
    end
end # function pcap_open_live

#----------
# compile a filter expression
#----------
function pcap_compile(handle, str; optimize=0, netmask=PCAP_NETMASK_UNKNOWN)
    program = bpf_program()
    result = ccall((:pcap_compile, :libpcap),
                   Cint,
                   (Ptr{pcap_t}, Ref{bpf_program}, Cstring, Cint, UInt32),
                   handle, program, str, optimize, netmask)
    if result == 0
        program
    else
        throw(ErrorException("pcap_compile: $(pcap_geterr(handle))"))
    end
end # function pcap_compile

#----------
# set the filter
#----------
function pcap_setfilter(handle, program)
    result = ccall((:pcap_setfilter, :libpcap),
                   Cint,
                   (Ptr{pcap_t}, Ref{bpf_program}),
                   handle, program)
    if result != 0
        throw(ErrorException("pcap_setfilter: $(pcap_geterr(handle))"))
    end
end # function pcap_setfilter

#----------
# read the next packet from a pcap_t
#----------
function pcap_next_ex(handle)
    pkt_header = Array{Ptr{pcap_pkthdr}}(undef, 1)
    pkt_data = Array{Ptr{UInt8}}(undef, 1)
    result = ccall((:pcap_next_ex, :libpcap),
                   Cint,
                   (Ptr{pcap_t}, Ptr{Ptr{pcap_pkthdr}}, Ptr{Ptr{UInt8}}),
                   handle, pkt_header, pkt_data)
    if result == -1
        throw(ErrorException("pcap_next_ex: $(pcap_geterr(handle))"))
    end

    if result == 1
        header = unsafe_load(pkt_header[1])
        data = unsafe_wrap(Array, pkt_data[1], header.caplen)
        (result, header, data)
    else
        (result, nothing, nothing)
    end
end # function pcap_next_ex

#----------
# transmit a packet
#----------
function pcap_inject(handle, pkt_data)
    result = ccall((:pcap_inject, :libpcap),
                   Cint,
                   (Ptr{pcap_t}, Ptr{UInt8}, Csize_t),
                   handle, pkt_data, length(pkt_data))
    if result == -1
        throw(ErrorException("pcap_inject: $(pcap_geterr(handle))"))
    else
        result
    end
end
