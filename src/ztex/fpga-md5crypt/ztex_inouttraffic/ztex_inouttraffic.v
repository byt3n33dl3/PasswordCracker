`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Used ISE version: 14.7
 *
 * md5crypt-ztex for John The Ripper password cracker -
 * bitstream for ZTEX 1.15y USB-FPGA module (4x Spartan-6 LX150)
 *
 */

module ztex_inouttraffic(
	input CS_IN,
	input [2:0] FPGA_ID,

	// Both IFCLK_IN and FXCLK_IN are at 48 MHz.
	input IFCLK_IN,
	input FXCLK_IN,

	// Vendor Command/Request I/O
	inout [7:0] PC, //  Vendor Command/Request (VCR) address/data
	input PA0,
	input PA1,
	input PA7,

	// High-Speed I/O Interface
	inout [15:0] FIFO_DATA,
	output FIFOADR0,
	output FIFOADR1,
	output SLOE,
	output SLRD,
	output SLWR,
	output PKTEND,
	input FLAGA,
	input FLAGB, // FULL
	input FLAGC, // EMPTY

	output INT4,
	output INT5
	);

	genvar i;


	// PC_RAW is available when VCR interface is off with cmd 0x00
	wire [7:0] PC_RAW = CS & vcr_inout_raw ? PC : 8'b0;

	reg error_r = 0; // Global error. Stop operation until GSR.

	clocks clocks(
		// Input clocks go to Clock Management Tile via dedicated routing
		.IFCLK_IN(IFCLK_IN),
		.FXCLK_IN(FXCLK_IN),
		// Up to 4 Programmable clocks
		.progen(PC_RAW[5:2]), .progdata(PC_RAW[1]), .progclk(PC_RAW[0]),
		.pll_reset(error_r), // Stop application clocks on error
		.progdone_inv(progdone_inv),
		// Produced clocks
		.IFCLK(IFCLK), 	// for operating I/O pins
		.PKT_COMM_CLK(),//PKT_COMM_CLK), // for I/O packet processing
		.core_clk_glbl_en(~idle),
		.CORE_CLK(CORE_CLK) // for operating computing units
	);

	assign PKT_COMM_CLK = CORE_CLK;

	chip_select chip_select(
		.CS_IN(CS_IN), .CLK(IFCLK), .CS(CS), .out_z_wait1(out_z_wait1)
	);

	wire [255:0] debug;
	wire [7:0] debug2, debug3;


	// ********************************************************
	//
	// Input buffer (via High Speed interface)
	//
	// ********************************************************
	wire [15:0] hs_input_din;
	wire [7:0] hs_input_dout;
	
	input_fifo input_fifo(
		.wr_clk(IFCLK),
		.din( {hs_input_din[7:0],hs_input_din[15:8]} ), // to Cypress IO
		.wr_en(hs_input_wr_en), // to Cypress IO
		.full(), // to Cypress IO
		.almost_full(hs_input_almost_full), // to Cypress IO
		.prog_full(hs_input_prog_full),

		.rd_clk(PKT_COMM_CLK),
		.dout(hs_input_dout),
		.rd_en(hs_input_rd_en),
		.empty(hs_input_empty)
	);	


	// ********************************************************
	//
	// Some example application
	// 16-bit input, 16-bit output
	//
	// ********************************************************
	wire [15:0] app_dout;
	wire [7:0] app_mode;
	wire [7:0] app_status, pkt_comm_status;
	
	md5crypt pkt_comm(
		.PKT_COMM_CLK(PKT_COMM_CLK),
		.CORE_CLK(CORE_CLK),
		// High-Speed FPGA input
		.din(hs_input_dout),
		.rd_en(hs_input_rd_en),
		.empty(hs_input_empty),
		// High-Speed FPGA output
		.dout(app_dout),
		.wr_en(app_wr_en),
		.full(app_full),
		// Application control (via VCR I/O). Set with fpga_set_app_mode()
		.app_mode(app_mode),
		// Application status. Available at fpga->wr.io_state.app_status
		.cores_idle(cores_idle),
		.app_status(app_status), .pkt_comm_status(pkt_comm_status),
		.debug2(debug2), .debug3(debug3)
	);

	always @(posedge IFCLK)
		error_r <= |pkt_comm_status | |app_status;

	// IDLE status: Turn off clock buffer (clock remains running).
	delay #(.INIT(1), .NBITS(8)) delay_idle_inst (.CLK(IFCLK),
		.in(~hs_input_wr_en // no write into input fifo (IFCLK)
			& output_fifo_idle // output "prepend" fifo is empty (IFCLK)
			& cores_idle_sync
		),
		.out(idle) );

	sync_sig sync_cores_idle( .sig(cores_idle),
		.clk(IFCLK), .out(cores_idle_sync) );


	// ********************************************************
	//
	// Output buffer (via High-Speed interface)
	//
	// ********************************************************
	wire [15:0] output_limit;
	wire [15:0] output_dout; // output via High-Speed Interface

	output_fifo output_fifo(
		.wr_clk(PKT_COMM_CLK),
		.din(app_dout),
		.wr_en(app_wr_en),
		.full(app_full), .idle(output_fifo_idle),

		.rd_clk(IFCLK),
		.dout(output_dout), // to Cypress IO,
		.rd_en(output_rd_en), // to Cypress IO,
		.empty(output_empty), // to Cypress IO
		.mode_limit(output_mode_limit),
		.reg_output_limit(reg_output_limit),
		.output_limit(output_limit),
		.output_limit_not_done(output_limit_not_done)
	);


	// ********************************************************
	//
	// High-Speed I/O Interface (Slave FIFO)
	//
	// ********************************************************
	wire [7:0] hs_io_timeout;

	hs_io_v2 #(
		.USB_ENDPOINT_IN(2),
		.USB_ENDPOINT_OUT(6)
	) hs_io_inst(
		.IFCLK(IFCLK), .CS(CS), .out_z_wait1(out_z_wait1), .EN(hs_en),
		.FIFO_DATA(FIFO_DATA), .FIFOADR0(FIFOADR0), .FIFOADR1(FIFOADR1),
		.SLOE(SLOE), .SLRD(SLRD), .SLWR(SLWR), .PKTEND(PKTEND),
		.FLAGA(FLAGA), .FLAGB(FLAGB), .FLAGC(FLAGC),
		// data output from Cypress IO, received by FPGA
		.dout(hs_input_din),	.wr_en(hs_input_wr_en),
		.almost_full(hs_input_almost_full),
		// to Cypress IO, out of FPGA
		.din(output_dout), .rd_en(output_rd_en), .empty(output_empty),
		.io_timeout(hs_io_timeout), .sfifo_not_empty(sfifo_not_empty),
		.io_fsm_error(io_fsm_error), .io_err_write(io_err_write)
	);


	// ********************************************************
	//
	// Vendor Command/Request (VCR) I/O interface
	//
	// ********************************************************
	wire [7:0] vcr_out;
	assign PC = CS && PA7 ? vcr_out : 8'bz;

	vcr vcr_inst(
		.CS(CS), .vcr_in(PC), .vcr_out(vcr_out),
		.clk_vcr_addr(PA0), .clk_vcr_data(PA1),
		// i/o goes with respect to IFCLK
		.IFCLK(IFCLK),
		// various inputs to be read by CPU
		.FPGA_ID(FPGA_ID),
		.hs_io_timeout(hs_io_timeout), .hs_input_prog_full(hs_input_prog_full),
		.sfifo_not_empty(sfifo_not_empty), .io_fsm_error(io_fsm_error), .io_err_write(io_err_write),
		.output_limit(output_limit), .output_limit_not_done(output_limit_not_done),
		.app_status(app_status),
		.pkt_comm_status(pkt_comm_status), .debug2(debug2), .debug3(debug3),
		//.debug(debug),
		.progdone_inv(progdone_inv), // Programmable clock
		// various control wires
		.inout_raw(vcr_inout_raw),
		.hs_en(hs_en),
		.output_mode_limit(output_mode_limit),
		.reg_output_limit(reg_output_limit),
		.app_mode(app_mode)
	);


	// External interrupts for USB controller - put into defined state
	assign INT4 = 1'b0;
	assign INT5 = 1'b1;

endmodule

