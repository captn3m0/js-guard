var activetab="", hostfull="", host="", header="", blstatus="", msg3="", msg4="", msg5="", msg6="", msg7="", msg8="";
//receiving (host,header,blsatus) from bg
framework.extension.getItem('count', function(value) {

	host=value;

});
/*
framework.extension.getItem('countHEAD', function(value) {

	header=value;
});
*/
/*
framework.extension.getItem('countBL', function(value) {

	blstatus=value;

});
*/

framework.extension.getItem('BIGcount', function(value) {
	hostfull=value[0];
	msg7=value[1];  //dyn hid ifr
	msg8=value[2]; //dyn sc req
  	msg3=value[3];  //tag encode
  	msg4=value[4]; //meta
  	msg5=value[5]; //ext domain
  	msg6=value[6]; //trackers
});
var y=[];
y.push(host);
y.push(header);
y.push(blstatus);
y.push(hostfull);
y.push(msg7);
y.push(msg8);
y.push(msg3);
y.push(msg4);
y.push(msg5);
y.push(msg6);

framework.extension.getItem('TAB', function(value) {
	activetab=value;

//newtab (first time)
if( activetab.match("chrome://newtab/") || activetab.match("chrome://extensions/") || activetab.match(hostfull)){  

	framework.extension.setItem(hostfull, JSON.stringify(y));	 	
              
}

//previously loaded and stored in the hostfull/activetab reference

else{            
	framework.extension.getItem(activetab, function(value) {
		
		if(value){
			var details=JSON.parse(value);
			host=details[0];
			header=details[1];
			blstatus=details[2];
			hostfull=details[3];
			msg7=details[4];
			msg8=details[5];
			msg3=details[6];
			msg4=details[7];
			msg5=details[8];
			msg6=details[9];	
		}
		else{
			blstatus="",host="",header="",msg3="",msg4="",msg5="",msg6="",msg7="",msg8="";
			//document.getElementById("cdac_domain").innerHTML=$.parseHTML("Reload the page to view details");
			$('#cdac_domain').html($.parseHTML("Reload the page to view details"));	
		}
	});
        
}

});


//updating panel

  


if(host){
        $('#cdac_domain').html($.parseHTML("<center>Analysis Report for "+host+"</center>"));
    }

    if(msg7){

        $('#cdac_one').html(msg7);
	$('#cdac_menuone').html($.parseHTML("<div>Hidden iframe(s) Redirections</div>"));
	$('#topCountone').html($.parseHTML("<div class='count'>  </div>"));
    }
    else{
       	$('#cdac_one').html($.parseHTML("No Hidden iframes"));
	$('#cdac_menuone').html($.parseHTML("<div>Hidden iframe(s) Redirections</div>"));
	$('#topCountone').html($.parseHTML("<div ></div>"));
    }
    if(msg8){
       	$('#cdac_two').html($.parseHTML(msg8));
	$('#cdac_menutwo').html($.parseHTML("<div>UnAuthorized Redirections</div>"));
	$('#topCounttwo').html("<div class='count'>  </div>");	
    }
    else{
       	$('#cdac_two').html($.parseHTML("No UnAuthorized Redirections"));
	$('#cdac_menutwo').html($.parseHTML("<div>UnAuthorized Redirections</div>"));
	$('#topCounttwo').html($.parseHTML("<div ></div>"));
    }
    if(msg3){
       	$('#cdac_three').html(msg3);
	$('#cdac_menuthree').html($.parseHTML("<div>Encoded JavaScript</div>"));
	$('#topCountthree').html($.parseHTML("<div class='count'>  </div>"));
    }
    else{
       	$('#cdac_three').html($.parseHTML("No Encoded JavaScript"));
	$('#cdac_menuthree').html($.parseHTML("<div>Encoded JavaScript</div>"));
	$('#topCountthree').html($.parseHTML("<div ></div>"));  
    }
    if(msg4){
       	$('#cdac_four').html($.parseHTML("<div style='color:red'>"+msg4+"</div>"+"<br><br>"+host+" links to the following External Domains:<br>"+msg5));
	$('#cdac_menufour').html($.parseHTML("<div>External Domain Requests</div>"));
	$('#topCountfour').html($.parseHTML("<div class='count'>  </div>"));
    }
    else if(msg5){
       	$('#cdac_four').html($.parseHTML(host+" links to the following External Domains:<br>"+msg5));
	$('#cdac_menufour').html($.parseHTML("<div>External Domain Requests</div>"));
	$('#topCountfour').html($.parseHTML("<div class='county'>  </div>"));
    }
    else{
      	$('#cdac_four').html($.parseHTML("No External Domain Requests"));
	$('#cdac_menufour').html($.parseHTML("<div>External Domain Requests</div>"));
	$('#topCountfour').html($.parseHTML("<div ></div>"));
    }
    if(msg6){
      	$('#cdac_five').html($.parseHTML(msg6));
	$('#cdac_menufive').html($.parseHTML("<div>Trackers</div>"));
	$('#topCountfive').html($.parseHTML("<div class='county'>  </div>"));
    }else{
       	$('#cdac_five').html($.parseHTML("No Trackers found"));
	$('#cdac_menufive').html($.parseHTML("<div>Trackers</div>"));
	$('#topCountfive').html($.parseHTML("<div ></div>")); 
    }

