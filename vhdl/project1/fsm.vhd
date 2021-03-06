-- fsm.vhd: Finite State Machine
-- fsm.vhd: Finite State Machine
-- Author(s): 
--
library ieee;
use ieee.std_logic_1164.all;
-- ----------------------------------------------------------------------------
--                        Entity declaration
-- ----------------------------------------------------------------------------
entity fsm is
port(
   CLK         : in  std_logic;
   RESET       : in  std_logic;

   -- Input signals
   KEY         : in  std_logic_vector(15 downto 0);
   CNT_OF      : in  std_logic;

   -- Output signals
   FSM_CNT_CE  : out std_logic;
   FSM_MX_MEM  : out std_logic;
   FSM_MX_LCD  : out std_logic;
   FSM_LCD_WR  : out std_logic;
   FSM_LCD_CLR : out std_logic
);
end entity fsm;

-- ----------------------------------------------------------------------------
--                      Architecture declaration
-- ----------------------------------------------------------------------------
architecture behavioral of fsm is
   type t_state is (TEST1,TEST2,TEST3,TEST4,TEST5,TEST6,TEST7,TEST8,TEST9,TEST10,TEST11,ERROR_MESSAGE,PRINT_ERROR, PRINT_MESSAGE,END_PROCCES, FINISH);
   signal present_state, next_state : t_state;

begin
-- -------------------------------------------------------
sync_logic : process(RESET, CLK)
begin
   if (RESET = '1') then
      present_state <= TEST1;
   elsif (CLK'event AND CLK = '1') then
      present_state <= next_state;
   end if;
end process sync_logic;

-- -------------------------------------------------------
next_state_logic : process(present_state, KEY, CNT_OF)
begin
   case (present_state) is
   -- - - - - - - - - - - - - - - - - - - - - - -
   when TEST1 =>
   	next_state <= TEST1;
      	if (KEY(1) = '1') then
	      next_state <= TEST2;  
	elsif(key(14 downto 0) /= "000000000000000") then
	  	next_state <= ERROR_MESSAGE;
	elsif(key(15) = '1') then
         next_state <= PRINT_ERROR; 
      	end if;
   -- - - - - - - - - - - - - - - - - - - - - - -
   when TEST2 =>
	next_state <= TEST2;
	if(key(3) ='1')then
		next_state <=TEST3;
	elsif(key(14 downto 0) /=  "000000000000000") then
	  	next_state <= ERROR_MESSAGE;
	elsif(key(15) = '1') then
		next_state <= PRINT_ERROR;
	end if;
    -- - - - - - - - - - - - - - - - - - - - - - -
   when TEST3 =>
	next_state <= TEST3;
	if(key(8)='1')then
		next_state <=TEST4;
	elsif(key(14 downto 0) /= "000000000000000") then
		next_state <= ERROR_MESSAGE;
	elsif(key(15)='1') then
		next_state <= PRINT_ERROR;
	end if;
   -- - - - - - - - - - - - - - - - - - - - - - -
   when TEST4 =>
   	next_state <= TEST4;
	if(key(1)='1')then
		next_state <=TEST5;
	elsif(key(14 downto 0) /= "000000000000000") then
		next_state <= ERROR_MESSAGE;
	elsif(key(15)='1') then
		next_state <=PRINT_ERROR;
	end if;
   -- - - - - - - - - - - - - - - - - - - - - - -
   when TEST5 =>
   	next_state <= TEST5;
	if(key(0)='1')then
		next_state <=TEST6;
	elsif(key(14 downto 0) /= "000000000000000") then
		next_state <= ERROR_MESSAGE;
	elsif(key(15)='1') then
		next_state <=PRINT_ERROR;
	end if;
    -- - - - - - - - - - - - - - - - - - - - - - -
   when TEST6 =>
	next_state <= TEST6;
	if(key(5)='1')then
		next_state <=TEST7;
	elsif(key(14 downto 0) /= "000000000000000") then
		next_state <= ERROR_MESSAGE;
	elsif(key(15)='1') then
		next_state <=PRINT_ERROR;
	end if;
    -- - - - - - - - - - - - - - - - - - - - - - 
   when TEST7 =>
	next_state <= TEST7;
	if(key(4)='1')then
		next_state <=TEST8;
	elsif(key(14 downto 0) /= "000000000000000") then
		next_state <= ERROR_MESSAGE;
	elsif(key(15)='1') then
		next_state <=PRINT_ERROR;
	end if;
    -- - - - - - - - - - - - - - - - - - - - - - 
   when TEST8=>
	next_state <= TEST8;
	if(key(0)='1')then
		next_state <=TEST9;
	elsif(key(14 downto 0) /= "000000000000000") then
		next_state <= ERROR_MESSAGE;
	elsif(key(15)='1') then
		next_state <=PRINT_ERROR;
	end if;
     -- - - - - - - - - - - - - - - - - - - - - -
   when TEST9=>
	next_state <= TEST9;
	if(key(3)='1') then
		next_state <=TEST10;
	elsif(key(14 downto 0) /= "000000000000000") then
		next_state <= ERROR_MESSAGE;
	elsif(key(15)='1') then
		next_state <=PRINT_ERROR;
	end if;
   -- - - - - - - - - - - - - - - - - - - - - -
   when TEST10=>
	next_state <= TEST10;
	if(key(3)='1')then
		next_state <=TEST11;
	elsif(key(14 downto 0) /= "000000000000000") then
		next_state <= ERROR_MESSAGE;
	elsif(key(15)='1') then
		next_state <=PRINT_ERROR;
	end if;
   -- - - - - - - - - - - - - - - - - - - - - - -
   when TEST11=>
	next_state <= TEST11;
	if(key(6)='1')then
		next_state <=END_PROCCES;
	elsif(key(14 downto 0) /= "000000000000000") then
		next_state <= ERROR_MESSAGE;
	elsif(key(15)='1') then
		next_state <=PRINT_MESSAGE;
	end if;
	
   -- - - - - - - - - - - - - - - - - - - - - - -
when END_PROCCES=>
	next_state <= END_PROCCES;
	if(key(15)='1') then
		next_state <=PRINT_MESSAGE;
	elsif(key(14 downto 0) /= "000000000000000") then
		next_state <= ERROR_MESSAGE;
	end if;
	
	
   -- - - - - - - - - - - - - - - - - - - - - - -
   when ERROR_MESSAGE=>
	   next_state <= ERROR_MESSAGE;
	if(KEY(15)='1') then
		next_state <=PRINT_ERROR;
	end if;
  
   -- - - - - - - - - - - - - - - - - - - - - - -
   when PRINT_MESSAGE =>
      next_state <= PRINT_MESSAGE;
      if (CNT_OF = '1') then
         next_state <= FINISH;
      end if;
   -- - - - - - - - - - - - - - - - - - - - - - -
   when PRINT_ERROR =>
	next_state <=PRINT_ERROR;
	if (CNT_OF = '1')then
	 	next_state <=FINISH;
	end if;	

   -- - - - - - - - - - - - - - - - - - - - - - -
   when FINISH =>
      next_state <= FINISH;
      if (KEY(15) = '1') then
         next_state <= TEST1; 
      end if;
   -- - - - - - - - - - - - - - - - - - - - - - -
   when others =>
      next_state <= TEST1;
   end case;
end process next_state_logic;

-- -------------------------------------------------------
output_logic : process(present_state, KEY)
begin
   FSM_CNT_CE     <= '0';
   FSM_MX_MEM     <= '0';
   FSM_MX_LCD     <= '0';
   FSM_LCD_WR     <= '0';
   FSM_LCD_CLR    <= '0';

   case (present_state) is
   -- - - - - - - - - - - - - - - - - - - - - - -
   when PRINT_MESSAGE =>
      FSM_MX_MEM     <= '1';
      FSM_CNT_CE     <= '1';
      FSM_MX_LCD     <= '1';
      FSM_LCD_WR     <= '1';
      
   -- - - - - - - - - - - - - - - - - - - - - - -
   when PRINT_ERROR =>
	FSM_CNT_CE <= '1';
	FSM_MX_LCD <= '1';
	FSM_LCD_WR <= '1';


   when FINISH =>
      if (KEY(15) = '1') then
         FSM_LCD_CLR    <= '1';
      end if;
   -- - - - - - - - - - - - - - - - - - - - - - -
   when others =>
	   if(KEY(14 downto 0) /= "000000000000000") then
		   FSM_LCD_WR <= '1';
	end if;
	if(KEY(15) ='1') then
		FSM_LCD_CLR <='1';
	end if;
   end case;
end process output_logic;

end architecture behavioral;

