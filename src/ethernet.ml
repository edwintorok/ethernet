(*
 * Copyright (c) 2010-2011 Anil Madhavapeddy <anil@recoil.org>
 * Copyright (c) 2011 Richard Mortier <richard.mortier@nottingham.ac.uk>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *)

module Packet = struct
  type proto = Ethernet_packet.proto
  let pp_proto = Ethernet_packet.pp_proto

  type t = Ethernet_packet.t =  {
    source : Macaddr.t;
    destination : Macaddr.t;
    ethertype : proto;
  }


  let sizeof_ethernet = Ethernet_packet.sizeof_ethernet

  let of_cstruct = Ethernet_packet.Unmarshal.of_cstruct

  let into_cstruct = Ethernet_packet.Marshal.into_cstruct

  let make_cstruct = Ethernet_packet.Marshal.make_cstruct
end

module type S = sig
  type nonrec error = private [> `Exceeds_mtu ]
  val pp_error: error Fmt.t
  type t
  val disconnect : t -> unit Lwt.t
  val write: t -> ?src:Macaddr.t -> Macaddr.t -> Packet.proto -> ?size:int ->
    (Cstruct.t -> int) -> (unit, error) result Lwt.t
  val mac: t -> Macaddr.t
  val mtu: t -> int
  val input:
    arpv4:(Cstruct.t -> unit Lwt.t) ->
    ipv4:(Cstruct.t -> unit Lwt.t) ->
    ipv6:(Cstruct.t -> unit Lwt.t) ->
    t -> Cstruct.t -> unit Lwt.t
end

open Lwt.Infix

let src = Logs.Src.create "ethernet" ~doc:"Mirage Ethernet"
module Log = (val Logs.src_log src : Logs.LOG)

module PacketQueue = Mirage_net.PacketQueue

module Make (Netif : Mirage_net.S) = struct

  type error = [ `Exceeds_mtu | `Netif of Netif.error ]
  let pp_error ppf = function
    | `Exceeds_mtu -> Fmt.string ppf "exceeds MTU"
    | `Netif e -> Netif.pp_error ppf e


  type t = {
    netif: Netif.t;
    device: PacketQueue.(device t);
    input:  PacketQueue.(input t);
    output: PacketQueue.(output t);
    promise: PacketQueue.(promise t)
  }

  let mac t = Netif.mac t.netif
  let mtu t = Netif.mtu t.netif (* interface MTU excludes Ethernet header *)

  let input ~arpv4 ~ipv4 ~ipv6 t frame =
    let open Ethernet_packet in
    let open Mirage_net in
    let of_interest dest =
      Macaddr.compare dest (mac t) = 0 || not (Macaddr.is_unicast dest)
    in
    PacketQueue.on_input t.input frame;
    let res =
    match Unmarshal.of_cstruct frame with
    | Ok (header, payload) when of_interest header.destination ->
      begin
        PacketQueue.on_promise t.promise ~size_in_bytes:(Cstruct.length frame) @@
        match header.Ethernet_packet.ethertype with
        | `ARP -> arpv4 payload
        | `IPv4 -> ipv4 payload
        | `IPv6 -> ipv6 payload
      end
    | Ok _ -> Lwt.return_unit
    | Error s ->
      Log.debug (fun f -> f "dropping Ethernet frame: %s" s);
      Lwt.return_unit
    in
    (* check before allocating next packet, while we still have a chance to avoid [OutOfMemory] *)
    if PacketQueue.get_free_bytes t.input <= 0 then begin
      Gc.compact ();
      Log.debug (fun f -> f "Memory pressure on input. After compaction: %d"
        (PacketQueue.get_free_bytes t.input))
    end;
    res

  let write t ?src destination ethertype ?size payload =
    let open Mirage_net in
    let source = match src with None -> mac t | Some x -> x
    and eth_hdr_size = Ethernet_packet.sizeof_ethernet
    and mtu = mtu t
    in
    match
      match size with
      | None -> Ok mtu
      | Some s -> if s > mtu then Error () else Ok s
    with
    | Error () -> Lwt.return (Error `Exceeds_mtu)
    | Ok size ->
      let size = eth_hdr_size + size in
      let hdr = { Ethernet_packet.source ; destination ; ethertype } in
      let fill frame =
        PacketQueue.on_output t.output frame;
        match Ethernet_packet.Marshal.into_cstruct hdr frame with
        | Error msg ->
          Log.err (fun m -> m "error %s while marshalling ethernet header into allocated buffer" msg);
          0
        | Ok () ->
          let len = payload (Cstruct.shift frame eth_hdr_size) in
          eth_hdr_size + len
      in
      (* check before allocating, while we still have a chance to avoid [OutOfMemory] *)
      if PacketQueue.get_free_bytes t.promise <= 0 ||
         PacketQueue.get_free_bytes t.output <= 0
      then begin
        Gc.compact ();
        Log.debug (fun f -> f "Memory pressure on output. After compaction: %d" (PacketQueue.get_free_bytes t.promise));
      end;
      PacketQueue.on_promise t.promise ~size_in_bytes:size @@
      Netif.write t.netif ~size fill >|= function
      | Ok () -> Ok ()
      | Error e ->
        Log.warn (fun f -> f "netif write errored %a" Netif.pp_error e) ;
        Error (`Netif e)

  let connect netif =
    let parent = PacketQueue.make_device () in
    let size_in_bytes = Netif.mtu netif + Ethernet_packet.sizeof_ethernet in
    let input = PacketQueue.make_input ~parent ~size_in_bytes ()
    and output = PacketQueue.make_output ~parent ()
    and promise = PacketQueue.make_promise ~parent () in
    let t = { netif; device = parent; input; output; promise } in
    Log.info (fun f -> f "Connected Ethernet interface %a" Macaddr.pp (mac t));
    Lwt.return t

  let disconnect t =
    Log.info (fun f -> f "Disconnected Ethernet interface %a" Macaddr.pp (mac t));
    Lwt.return_unit
end
