function install_notice() {
			    if (localStorage.getItem('install_time'))
			        return;

			    var now = new Date().getTime();
			    localStorage.setItem('install_time', now);
			    chrome.tabs.create({url: "release-notes.html"});
			}
			install_notice();

//receiving host from dD.js, getiing header and blstatus and sending(host,header,blsatus) to popup
framework.extension.attachEvent('HI', function(e){

	var path=e.data.someData;

	framework.extension.setItem('count', e.data.someData); //sending host to popup

	//header
/*	var xhr =framework.extension.getRequest();

	xhr.open("GET", path , true);

	xhr.onreadystatechange = function(){

	var headers="";

	  if (xhr.readyState === 4) {

	    if (xhr.status === 200) {

		headers = xhr.getAllResponseHeaders().toLowerCase();

		framework.extension.setItem('countHEAD', headers);     //sending header to popup

	    } else {
     		// framework.extension.log('error: '+xhr.statusText);
	    }
	  }
  
	};

	xhr.send(null);
	*/

	//blstatus
/*	var newpath="1\n"+e.data.someData;

	var xhrr =framework.extension.getRequest();

	//xhrr.open('POST', 'https://sb-ssl.google.com/safebrowsing/api/lookup?client=firefox&apikey=ABQIAAAAxhNVFd2Bkr2PLooc8AycwBRHPfqIBBZIjrF8eFFZCSSGcCk3eg&appver=1.5.2&pver=3.0', true);

	xhrr.open('POST', 'https://sb-ssl.google.com/safebrowsing/api/lookup?client=firefox&apikey=ABQIAAAAbdp4DqroP2NK_67G6Dil3hQGYhg9gq_RVOA_hJObqyVgDHG3XQ&appver=1.5.2&pver=3.0', true);

	xhrr.onreadystatechange = function(){

		var blstatus="";

		if (xhrr.readyState === 4) {

			if (xhrr.status === 200) {

				blstatus = xhrr.responseText;
				framework.extension.fireEvent('RE', { data: {url:e.data.someData, someData:blstatus, highlitedText:'CNN'}}); //hostname
	
				framework.extension.setItem('countBL', blstatus);    //sending blstatus to popup

			} else {
	     			// framework.extension.log('error: '+xhr.statusText);
				framework.extension.fireEvent('RE', { data: {url:e.data.someData, someData:blstatus, highlitedText:'CNN'}}); //hostname
	
				framework.extension.setItem('countBL', blstatus);    //sending blstatus to popup
	    		}
		}

		
	};

	xhrr.send(newpath);*/

});


//blstatus for ifr
framework.extension.attachEvent('status_if', function(e){

	var newifpath=e.data.someData;
	
	var xhrr =framework.extension.getRequest();

	xhrr.open('POST', 'https://sb-ssl.google.com/safebrowsing/api/lookup?client=firefox&apikey=ABQIAAAAxhNVFd2Bkr2PLooc8AycwBRHPfqIBBZIjrF8eFFZCSSGcCk3eg&appver=1.5.2&pver=3.0', true);

	xhrr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');

	xhrr.onreadystatechange = function(){

	var blstatus_if="";

	if (xhrr.readyState === 4) {

	    if (xhrr.status === 200) {

		blstatus_if = xhrr.responseText;

		framework.extension.setItem('ifgsbstat', blstatus_if);    //send to dD.js to i. check b4 giving js request alert and  ii. in else case give alert
		
		framework.extension.fireEvent('ifgsbstat', { data: {someData:blstatus_if,highlitedText:'CNN'}});

	    } else {
		     // framework.extension.log('error: '+xhr.statusText);
	    }
	  }

	};

	xhrr.send(newifpath);

});

//blstatus for sc
framework.extension.attachEvent('status_sc', function(e){

	var newifpath=e.data.someData;
	
	var xhrr =framework.extension.getRequest();

	xhrr.open('POST', 'https://sb-ssl.google.com/safebrowsing/api/lookup?client=firefox&apikey=ABQIAAAAxhNVFd2Bkr2PLooc8AycwBRHPfqIBBZIjrF8eFFZCSSGcCk3eg&appver=1.5.2&pver=3.0', true);

	xhrr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');

	xhrr.onreadystatechange = function(){

	var blstatus_sc="";

	if (xhrr.readyState === 4) {

	    if (xhrr.status === 200) {

		blstatus_sc = xhrr.responseText;

		framework.extension.setItem('scgsbstat', blstatus_sc);    //send to dD.js to i. check b4 giving js request alert and  ii. in else case give alert
		
		framework.extension.fireEvent('scgsbstat', { data: {someData:blstatus_sc,highlitedText:'CNN'}});

	    } else {
		     // framework.extension.log('error: '+xhr.statusText);
	    }
	  }

	};

	xhrr.send(newifpath);

});
//sending details to popup
framework.extension.attachEvent('BIGHI', function(e){

	framework.extension.setItem('BIGcount', e.data.someData);

});

framework.browser.attachEvent('TabChanged', function (e) {
//alert("active tab: "+e.url);
framework.extension.setItem('TAB', e.url);
});


options = {url: 'popup.html', width: 285, height: 520};

framework.ui.button.setPopup(options);
