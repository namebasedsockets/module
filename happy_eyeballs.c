
#include "happy_eyeballs.h"

static int p = 0;

void happy_eyeballs_init(void){
	p = 0;
}

int happy_eyeballs_af_pref(void){
	return (p);
}

void happy_eyeballs_v6_success(void){
	if( p >= 0 ){
		p = p + 1;
	}
	else if( p < 0) {
		p = (p / 2);
	} 
}

void happy_eyeballs_v4_success(void){
	if( p <= 0 ){
		p = p - 1;
	}
	else if (p > 0) {
		p = (p / 2);
	}
}