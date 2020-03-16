var Hosturl="", fullurl="", Taburl="";
var y=[], z=[];
function connected(portFromCS) {
	portFromCS.onMessage.addListener(function(m) {
    	if(m.url){
		Hosturl=m.url;
		fullurl=m.fullurl;
		console.log("background script received url message "+ Hosturl+" and fullurl msg: "+fullurl);
	}
	if(m.popupinfo){
		y=m.popupinfo;
	}

		


	// the below 2 can be combined as both sent to popup
	if(m.request_url){
		//console.log("background script received a url requestform popup so sending from hosturl "+Hosturl);
		portFromCS.postMessage({"url_response":Hosturl,"fullurl_response":fullurl});
		//portFromCS.postMessage({"url_response":Hosturl,"activeurl_response":Taburl});
	}
	if(m.request_popupdata){
		//console.log("background script received a popup data request form popup so sending from y"+y);
		portFromCS.postMessage({"popupdata":y});
	}

  });
}

browser.runtime.onConnect.addListener(connected);


