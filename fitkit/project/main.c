//Author: Tomáš Èikel
//Login: xcikel00
//Date: 22.12.2019

#include "MK60D10.h"

#include <stdio.h>
#include <stdbool.h>
/* Macros for bit-level registers manipulation */
#define GPIO_PIN_MASK 0x1Fu
#define GPIO_PIN(x) (((1)<<(x & GPIO_PIN_MASK)))

/* Mapping of LEDs and buttons to specific port pins: */
// Note: only D9, SW3 and SW5 are used in this sample app

#define LED_D9  0x20      // Port B, bit 5
#define LED_D10 0x10      // Port B, bit 4
#define LED_D11 0x8       // Port B, bit 3
#define LED_D12 0x4       // Port B, bit 2

#define BTN_SW2 0x400     // Port E, bit 10
#define BTN_SW3 0x1000    // Port E, bit 12
#define BTN_SW4 0x8000000 // Port E, bit 27
#define BTN_SW5 0x4000000 // Port E, bit 26
#define BTN_SW6 0x800     // Port E, bit 11

#define SPK 0x10          // Speaker is on PTA4

int pressed_up = 0, pressed_down = 0;
int beep_flag = 0;
//LPTMR timer
unsigned int compare = 0xF0;
//RTC interrupt timer
int starttime=1;
//count interrupts of rtc and lptmr
int cuountrtc=0;
int countlptmr=0;

int testarray[7];



void delay(uint64_t bound) {
	for (uint64_t i=0; i < bound; i++) { __NOP(); }
}

/* Initialize the MCU - basic clock settings, turning the watchdog off */
void MCUInit(void)  {
    MCG_C4 |= ( MCG_C4_DMX32_MASK | MCG_C4_DRST_DRS(0x01) );
    SIM_CLKDIV1 |= SIM_CLKDIV1_OUTDIV1(0x00);
    WDOG_STCTRLH &= ~WDOG_STCTRLH_WDOGEN_MASK;
}

void PortsInit(void)
{
    /* Turn on all port clocks */
    SIM->SCGC5 = SIM_SCGC5_PORTB_MASK | SIM_SCGC5_PORTE_MASK | SIM_SCGC5_PORTA_MASK;
    SIM->SCGC6 =  SIM_SCGC6_RTC_MASK ;

    /* Set corresponding PTB pins (connected to LED's) for GPIO functionality */
       PORTB->PCR[5] = PORT_PCR_MUX(0x01); // D9
       PORTB->PCR[4] = PORT_PCR_MUX(0x01); // D10
       PORTB->PCR[3] = PORT_PCR_MUX(0x01); // D11
       PORTB->PCR[2] = PORT_PCR_MUX(0x01); // D12


       PORTA->PCR[4] = PORT_PCR_MUX(0x01);  // Speaker

       /* Change corresponding PTB port pins as outputs */
       PTB->PDDR = GPIO_PDDR_PDD(0x3C);     // LED ports as outputs
       PTA->PDDR = GPIO_PDDR_PDD(SPK);     // Speaker as output
       PTB->PDOR |= GPIO_PDOR_PDO(0x3C);    // turn all LEDs OFF
       PTA->PDOR &= GPIO_PDOR_PDO(~SPK);   // Speaker off, beep_flag is false
}

void LPTMR0_IRQHandler(void)
{

    LPTMR0_CSR |=  LPTMR_CSR_TCF_MASK;   // writing 1 to TCF tclear the flag
    GPIOB_PDOR ^= LED_D9;
    GPIOB_PDOR ^= LED_D10;
    countlptmr += 1;

}

void LPTMR0Init(int count)
{
	 SIM_SCGC5 |= SIM_SCGC5_LPTIMER_MASK; // Enable clock to LPTMR
	    LPTMR0_CSR &= ~LPTMR_CSR_TEN_MASK;   // Turn OFF LPTMR to perform setup
	    LPTMR0_PSR = ( LPTMR_PSR_PRESCALE(0) // 0000 is div 2
	                 | LPTMR_PSR_PBYP_MASK   // LPO feeds directly to LPT
	                 | LPTMR_PSR_PCS(1)) ;   // use the choice of clock
	    LPTMR0_CMR = count;                  // Set compare value
	    LPTMR0_CSR =(  LPTMR_CSR_TCF_MASK    // Clear any pending interrupt (now)
	                 | LPTMR_CSR_TIE_MASK    // LPT interrupt enabled
	                );
	    NVIC_EnableIRQ(LPTMR0_IRQn);         // enable interrupts from LPTMR0
	    LPTMR0_CSR |= LPTMR_CSR_TEN_MASK;
}


void RTC_IRQHandler() {
    if(RTC_SR & RTC_SR_TAF_MASK) {
        GPIOB_PDOR ^= LED_D11;
        GPIOB_PDOR ^= LED_D12;
            RTC_TAR += 1; //move interrupt timer
            cuountrtc +=1;
    }
    }

void RTCInit() {

    RTC_CR |= RTC_CR_SWR_MASK;  // SWR = 1, reset all RTC's registers
    RTC_CR &= ~RTC_CR_SWR_MASK; // SWR = 0

    RTC_TCR = 0x0000; // reset CIR and TCR

    RTC_CR |= RTC_CR_OSCE_MASK; // enable 32.768 kHz oscillator


    RTC_SR &= ~RTC_SR_TCE_MASK; // turn OFF RTC

    RTC_TSR = 0x00000000; // MIN value in 32bit register
    RTC_TAR = 0x00000001; // MAX value in 32bit register

    RTC_IER |= RTC_IER_TAIE_MASK;

    NVIC_ClearPendingIRQ(RTC_IRQn);
    NVIC_EnableIRQ(RTC_IRQn);

    RTC_SR |= RTC_SR_TCE_MASK; // turn ON RTC
}



//Testing ram using March algorithm, each LED represents state of the test
void testram(){
	 GPIOB_PDOR ^= LED_D9;             // First state
	 delay(900000);
	 for(int i=0;i<8;i++){ 					// insert 0
		 testarray[i]=0;
	 }
	 GPIOB_PDOR ^= LED_D10;              //Second state
	 delay(900000);
	 for(int i=0;i<8;i++){				// check the value for 0 and insert 1
		 if(testarray[i]==0){
			 testarray[i]=1;
		 }
		 else{
			 GPIOB_PDOR ^= LED_D9;			// clear LEDS
			 GPIOB_PDOR ^= LED_D10;
			 return;
		 }
	 }
	 GPIOB_PDOR ^= LED_D11;				//Third state
	 delay(900000);
	 for(int i=7;i>1;i--){
		 if(testarray[i]==1){
			 testarray[i]=0;
		 }
		 else{
			 GPIOB_PDOR ^= LED_D9;			// clear LEDS
			 GPIOB_PDOR ^= LED_D10;
			 GPIOB_PDOR ^= LED_D11;
			 delay(900000);
			 return;
		 }
	 }
	 GPIOB_PDOR ^= LED_D12; 			//End of test
	 delay(900000);
	 GPIOB_PDOR ^= LED_D9;			// clear LEDS
	 GPIOB_PDOR ^= LED_D10;
	 GPIOB_PDOR ^= LED_D11;
	 GPIOB_PDOR ^= LED_D12;
}

//Test function of LPTMR
void testlpmtr(){
	//compare it with RTC
	if(countlptmr>(cuountrtc+1)*5){
		delay(900000);
			GPIOB_PDOR ^= LED_D11;
			GPIOB_PDOR ^= LED_D12;
			delay(900000);
	}
	//check if clock is working
	else if(countlptmr==0){
		delay(900000);
					GPIOB_PDOR ^= LED_D10;
					GPIOB_PDOR ^= LED_D9;
					delay(900000);
	}

	//if everything is working display all LEDs
	else{
		delay(1000000);
		GPIOB_PDOR ^= LED_D9;			// clear LEDS
					GPIOB_PDOR ^= LED_D10;
		GPIOB_PDOR ^= LED_D11;
					GPIOB_PDOR ^= LED_D12;
					delay(1000000);
	}

	//refresh counters
	cuountrtc=0;
	countlptmr=0;
	return ;
}
int main(void)
{
    MCUInit();
    PortsInit();
    LPTMR0Init(compare);
    RTCInit();

    while (1) {
    	//stop Clocks so they dont toggle LEDs
        RTC_SR &= ~RTC_SR_TCE_MASK;
        LPTMR0_CSR &= ~LPTMR_CSR_TEN_MASK;

        //turn off LEDs
        GPIOB_PDOR =0xFF;
        delay(9000000);

        //Test ram
    	testram();

    	//Turn on Clocks and let them run for a while
    	RTC_SR |= RTC_SR_TCE_MASK;
        LPTMR0_CSR |= LPTMR_CSR_TEN_MASK;
        delay(9000000);

        //Turn off Clocks
        RTC_SR &= ~RTC_SR_TCE_MASK;
        LPTMR0_CSR &= ~LPTMR_CSR_TEN_MASK;
        GPIOB_PDOR =0xFF;
        delay(9000000);

        //Test LPTMR
        testlpmtr();
        RTC_SR |= RTC_SR_TCE_MASK;
        LPTMR0_CSR |= LPTMR_CSR_TEN_MASK;
        delay(10000000);

    }

    return 0;
}
