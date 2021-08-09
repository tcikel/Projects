library IEEE;
use IEEE.std_logic_1164.all;
use IEEE.std_logic_arith.all;
use IEEE.std_logic_unsigned.all;

entity ledc8x8 is
port ( -- Sem doplnte popis rozhrani obvodu.
	ROW	: out std_logic_vector (0 to 7);
	LED	: out std_logic_vector (0 to 7);
	RESET: in std_logic;
	SMCLK: in std_logic
);
end ledc8x8;


architecture main of ledc8x8 is
	signal rows: std_logic_vector(7 downto 0) := "00000000";
	signal column: std_logic_vector(7 downto 0) := "00000000";
	signal mux: std_logic := '0';
	signal mux2: std_logic_vector(1 downto 0):= "00";
   	signal counter: std_logic_vector(7 downto 0) := "00000000";
	signal delaycounter : std_logic_vector(20 downto 0) :="000000000000000000000";	
-- Sem doplnte definice vnitrnich signalu.

begin
	smclkpro: process(RESET,SMCLK) 
	begin 
		if RESET='1' then
			counter<="00000000";
		elsif SMCLK'event and SMCLK ='1' then
				counter <=counter+1;
				if counter = "11111111" then
					mux<='1';
				else 
					mux<='0';
				end if;
			end if;
	end process;

----------------------------------------------------------------------

	delay: process(SMCLK,RESET,delaycounter,mux2)
	begin 
		if RESET='1' then
			delaycounter <="000000000000000000000";
		
		elsif SMCLK = '1' AND SMCLK'event then
				delaycounter <= delaycounter + '1';
			if delaycounter = "111000010000000000000"   then	
				mux2<=mux2 +'1';
				delaycounter<="000000000000000000000";
	
			end if;

			LED <= column;
		end if;
	end process;


-----------------------------------------------------------------------


	rotate: process(RESET,SMCLK,mux,rows)
	begin
		if RESET='1' then
			rows <= "10000000";
		elsif(SMCLK ='1' and SMCLK'event and mux ='1')then
			rows <= rows(0) & rows(7 downto 1);
		end if;
		ROW <=rows;
	end process;

	

-----------------------------------------------------------------------



	showled :process(rows,mux2)
	begin
			
			
			if mux2= "00"  then
			
				case rows is
					when "10000000" => column <= "00000001";
					when "01000000" => column <= "11101111";
					when "00100000" => column <= "11101111";
					when "00010000" => column <= "11101111";
					when "00001000" => column <= "11101111";
					when "00000100" => column <= "11101111";
					when "00000010" => column <= "11101111";
					when "00000001" => column <= "11101111";
					when others => column <= "11111111";
				end case;
						
					 
			elsif mux2="10" then


				case rows is	
					when "10000000" => column <= "10000001";
					when "01000000" => column <= "01111111";
					when "00100000" => column <= "01111111";
					when "00010000" => column <= "01111111";
					when "00001000" => column <= "01111111";
					when "00000100" => column <= "01111111";
					when "00000010" => column <= "01111111";
					when "00000001" => column <= "10000001";
					when others => column <= "11111111";
				end case;
			else
				 column <= "11111111";

			end if;
		
			

	end process;
	
	
	

-- Sem doplnte popis obvodu. Doporuceni: pouzivejte zakladni obvodove prvky
    -- (multiplexory, registry, dekodery,...), jejich funkce popisujte pomoci
    -- procesu VHDL a propojeni techto prvku, tj. komunikaci mezi procesy,
    -- realizujte pomoci vnitrnich signalu deklarovanych vyse.

    -- DODRZUJTE ZASADY PSANI SYNTETIZOVATELNEHO VHDL KODU OBVODOVYCH PRVKU,
    -- JEZ JSOU PROBIRANY ZEJMENA NA UVODNICH CVICENI INP A SHRNUTY NA WEBU:
    -- http://merlin.fit.vutbr.cz/FITkit/docs/navody/synth_templates.html.

    -- Nezapomente take doplnit mapovani signalu rozhrani na piny FPGA
    -- v souboru ledc8x8.ucf.

end main;
