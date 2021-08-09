-- cpu.vhd: Simple 8-bit CPU (BrainF*ck interpreter)
-- Copyright (C) 2018 Brno University of Technology,
--                    Faculty of Information Technology
-- Author(s): Tomáš Èikel - xcikel00
--

library ieee;
use ieee.std_logic_1164.all;
use ieee.std_logic_arith.all;
use ieee.std_logic_unsigned.all;

-- ----------------------------------------------------------------------------
--                        Entity declaration
-- ----------------------------------------------------------------------------
entity cpu is
 port (
   CLK   : in std_logic;  -- hodinovy signal
   RESET : in std_logic;  -- asynchronni reset procesoru
   EN    : in std_logic;  -- povoleni cinnosti procesoru
 
   -- synchronni pamet ROM
   CODE_ADDR : out std_logic_vector(11 downto 0); -- adresa do pameti
   CODE_DATA : in std_logic_vector(7 downto 0);   -- CODE_DATA <- rom[CODE_ADDR] pokud CODE_EN='1'
   CODE_EN   : out std_logic;                     -- povoleni cinnosti
   
   -- synchronni pamet RAM
   DATA_ADDR  : out std_logic_vector(9 downto 0); -- adresa do pameti
   DATA_WDATA : out std_logic_vector(7 downto 0); -- mem[DATA_ADDR] <- DATA_WDATA pokud DATA_EN='1'
   DATA_RDATA : in std_logic_vector(7 downto 0);  -- DATA_RDATA <- ram[DATA_ADDR] pokud DATA_EN='1'
   DATA_RDWR  : out std_logic;                    -- cteni z pameti (DATA_RDWR='1') / zapis do pameti (DATA_RDWR='0')
   DATA_EN    : out std_logic;                    -- povoleni cinnosti
   
   -- vstupni port
   IN_DATA   : in std_logic_vector(7 downto 0);   -- IN_DATA obsahuje stisknuty znak klavesnice pokud IN_VLD='1' a IN_REQ='1'
   IN_VLD    : in std_logic;                      -- data platna pokud IN_VLD='1'
   IN_REQ    : out std_logic;                     -- pozadavek na vstup dat z klavesnice
   
   -- vystupni port
   OUT_DATA : out  std_logic_vector(7 downto 0);  -- zapisovana data
   OUT_BUSY : in std_logic;                       -- pokud OUT_BUSY='1', LCD je zaneprazdnen, nelze zapisovat,  OUT_WE musi byt '0'
   OUT_WE   : out std_logic                       -- LCD <- OUT_DATA pokud OUT_WE='1' a OUT_BUSY='0'
 );
end cpu;


-- ----------------------------------------------------------------------------
--                      Architecture declaration
-- ----------------------------------------------------------------------------
architecture behavioral of cpu is

	signal pc_addr: std_logic_vector(11 downto 0);
	signal pc_inc: std_logic;
	signal pc_dec: std_logic;


	signal ptr_addr: std_logic_vector(9 downto 0);
       	signal ptr_inc: std_logic;
	signal ptr_dec: std_logic;
	

	signal cnt_addr: std_logic_vector(7 downto 0);
	signal cnt_inc: std_logic;
	signal cnt_dec: std_logic;
 
	type fsm_state is ( 
	INIT,INC,DEC,INCDATA,INCDATA2,DECDATA,DECDATA2,PRINT,PRINT1,READ,DECODE,COMMENT,COMMENT1,COMMENT2,WHILESTART,WHILESTART1,INSIDEWHILE,INSIDEWHILE2,WHILEEND,WHILEEND1,WHILEEND2,WHILEEND3,WHILEEND4,WHILEEND5,HEXA,ENDPROGRAM,OTHER
	);
	signal currentstate: fsm_state;	
	signal nextstate: fsm_state;
	signal mux : std_logic_vector(1 downto 0);
	signal hex_vector : std_logic_vector( 7 downto 0);
 -- zde dopiste potrebne deklarace signalu

begin

 -- zde dopiste vlastni VHDL kod dle blokoveho schema

 -- inspirujte se kodem procesoru ze cviceni


	mx: process(CLK, DATA_RDATA,mux, IN_DATA)
	begin 
		case mux is 
			when "00" => DATA_WDATA <= IN_DATA;
			when "01" => DATA_WDATA <= DATA_RDATA +1;
			when "10" => DATA_WDATA <= DATA_RDATA -1;
			when "11" => DATA_WDATA <= hex_vector;
			when others =>
		end case;
	end process;
	

	reg_pc: process (RESET, CLK)
	begin
		if(RESET='1') then
			pc_addr <= (others=>'0');
		elsif (CLK'event) and (CLK='1') then
			if (pc_inc = '1') then
				pc_addr <= pc_addr + 1;
			elsif (pc_dec ='1') then
				pc_addr <= pc_addr - 1;
			end if;
		end if;
	end process;

	

	reg_ptr: process (RESET, CLK)
	begin 
		if(RESET='1') then
			ptr_addr <= (others=>'0');
		elsif (CLK'event) and (CLK='1') then
			if (ptr_inc ='1') then
				ptr_addr <= ptr_addr +1;
			elsif( ptr_dec ='1') then
				ptr_addr <= ptr_addr -1;
			end if;
		end if;
	end process;

	DATA_ADDR <= ptr_addr;
	CODE_ADDR <= pc_addr;

	reg_cnt: process(RESET,CLK)
	begin
		if(RESET='1') then
			cnt_addr <= (others=>'0');
		elsif (CLK'event) and (CLK='1') then
			if(cnt_inc='1') then
				cnt_addr <= cnt_addr +1;
			elsif(cnt_dec='1') then
				cnt_addr <= cnt_addr -1;
			end if;
		end if;
	end process;



	fsm_currenstate_proces: process(RESET,CLK)
	begin 
		if(RESET='1') then
			currentstate <=INIT;	
		elsif( CLK'event and CLK = '1') then
			if(EN='1') then
				currentstate <=nextstate;
			end if;
		end if;
	end process;


	fsm_nextstate_proces:  process(currentstate,CLK,RESET,CODE_DATA,DATA_RDATA,OUT_BUSY,mux,cnt_addr)
	begin
		nextstate <= INIT;
		CODE_EN <= '1';
		ptr_inc <= '0';
		ptr_dec <= '0';
		cnt_inc <= '0';
		cnt_dec <= '0';
		pc_inc <= '0';
		pc_dec <= '0';
		IN_REQ <= '0';
		DATA_RDWR<= '0';
		DATA_EN <= '0';
		OUT_WE <= '0';
		mux <= "00";



		case currentstate is
			when INIT =>
			       nextstate <=DECODE;

		       	when DECODE =>
				CASE CODE_DATA is
					when X"3E" => 
						nextstate <= INC;
					when X"3C" =>
						nextstate <= DEC;
					when X"2B" =>
						nextstate <= INCDATA;
					when X"2D" =>
						nextstate <= DECDATA;
					when X"2E" => 
						nextstate <= PRINT;
					when X"2C" =>
						nextstate <= READ;
					when X"23" => 
						nextstate <= COMMENT;
					when X"5B" => 
						nextstate <= WHILESTART;
					when X"5D" => 
						nextstate <= WHILEEND;
					when X"30" => nextstate <= HEXA;
					when X"31" => nextstate <= HEXA;
					when X"32" => nextstate <= HEXA;
					when X"33" => nextstate <= HEXA;
					when X"34" => nextstate <= HEXA;
					when X"35" => nextstate <= HEXA;
					when X"36" => nextstate <= HEXA;
					when X"37" => nextstate <= HEXA;
					when X"38" => nextstate <= HEXA;
					when X"39" => nextstate <= HEXA;
					when X"41" => nextstate <= HEXA;
					when X"42" => nextstate <= HEXA;
					when X"43" => nextstate <= HEXA;
					when X"44" => nextstate <= HEXA;
					when X"45" => nextstate <= HEXA;
					when X"46" => nextstate <= HEXA;
					WHEN X"00" => 
						nextstate <= ENDPROGRAM;
					when others => 
						nextstate <=OTHER;

					end case;
			when INC =>
				ptr_inc <= '1';
				pc_inc <= '1';
				nextstate <=INIT;
			when DEC => 
				ptr_dec <= '1';
				pc_inc <= '1';
				nextstate <= INIT;

			when DECDATA => 
				DATA_RDWR <= '1';
				DATA_EN <= '1';
				nextstate <= DECDATA2;
			 
			when DECDATA2 => 
				mux <= "10";
				pc_inc <= '1';
				DATA_EN <= '1';
				DATA_RDWR <='0';
				nextstate <= INIT;

			when INCDATA => 
				DATA_RDWR <='1';
				 DATA_EN <= '1';
				nextstate <= INCDATA2;

			when INCDATA2 =>
				mux <= "01";
				pc_inc <= '1';
				DATA_EN <= '1';
				DATA_RDWR <='0';
				nextstate <= INIT;

			when PRINT =>
					DATA_EN <='1';
					DATA_RDWR <= '1';
					nextstate <= PRINT1;
			when PRINT1 => 
				if OUT_BUSY ='0' then
					OUT_DATA <= DATA_RDATA;
					OUT_WE<= '1';
					pc_inc <= '1';
					nextstate <= INIT;
				else
					DATA_EN <= '1';
					DATA_RDWR <= '1';
					nextstate <=PRINT1;
				end if;
				
			when READ =>
				IN_REQ <= '1';
				if(IN_VLD='1') then
					pc_inc <= '1';
					mux <= "00";
					DATA_EN <= '1';
					DATA_RDWR <= '0';
					nextstate <= INIT;
				else
					nextstate <=READ;
				end if;

			when COMMENT =>
				pc_inc <='1';
				nextstate <=COMMENT1;
			when COMMENT1 => 
				CODE_EN <='1';
				nextstate <=COMMENT2;
			when COMMENT2 =>
				if(CODE_DATA=X"23") then
				pc_inc <='1';
				nextstate <= INIT;
				else
					nextstate <= COMMENT;
				end if;

			when WHILESTART =>
				DATA_EN <='1';
				DATA_RDWR <='1';
				pc_inc <='1';
				nextstate <=WHILESTART1;

			when WHILESTART1 => 
				if(DATA_RDATA="00000000") then
					cnt_inc <= '1';
					nextstate <= INSIDEWHILE;
				else
					nextstate <= INIT;
				end if;

			when INSIDEWHILE => 
				if(cnt_addr/="00000000") then
					CODE_EN <= '1';
					nextstate <= INSIDEWHILE2;
				else
					nextstate <= INIT;
				end if;
			
			when INSIDEWHILE2 =>
					if(CODE_DATA=X"5B") then
						cnt_inc <= '1';
					elsif(CODE_DATA=X"5D") then
						cnt_dec <= '1';
					end if;
					pc_inc <= '1';
					nextstate <= INSIDEWHILE;

			when WHILEEND =>
				DATA_EN <='1';
				DATA_RDWR <='1';
				nextstate<=WHILEEND1;

			when WHILEEND1 =>
				if(DATA_RDATA="00000000") then
					pc_inc <= '1';
					nextstate <= INIT;
				else
					nextstate <= WHILEEND2;
				end if;

			when WHILEEND2 =>
				cnt_inc <='1';
				pc_dec <= '1';
				nextstate<= WHILEEND3;

			when WHILEEND3 => 
			      
				if(cnt_addr/="00000000") then
					CODE_EN <= '1';
					nextstate <= WHILEEND4;
				else
					nextstate <= INIT;
				end if;

			when WHILEEND4 =>
					if(CODE_DATA=X"5D") then
						cnt_inc <= '1';
					elsif(CODE_DATA=X"5B") then
						cnt_dec <= '1';
					end if;
				nextstate<= WHILEEND5;


			when WHILEEND5 =>	

				if(cnt_addr="00000000") then
					pc_inc <= '1';
				else
					pc_dec <= '1';
				end if;
				nextstate <=WHILEEND3;
					
			when HEXA => 
				DATA_EN <='1';
				mux <= "11";
				pc_inc <='1';
				if(CODE_DATA>X"40") then
				hex_vector <= (CODE_DATA(3 downto 0)+ std_logic_vector(conv_unsigned(9,hex_vector'LENGTH)(3 DOWNTO 0))) & "0000";
				else
				hex_vector <= CODE_DATA(3 downto 0) & "0000";
				end if;	
				nextstate <= INIT;

			when ENDPROGRAM => 
				nextstate <= ENDPROGRAM;
			when OTHER => 
				pc_inc <='1';
				nextstate <= INIT;

			when others => null;

		end case;
	end process;


end behavioral;
 
