var activetab = "", hostheader = "", host = "", fullurl = "", msg1 = "", msg2 = "", msg3 = "", msg4 = "", msg5 = "", msg6 = "", msg7 = "", msg8 = "", msg9 = "", msg10 = "";

/*function updateContent2() {
			browser.tabs.query({currentWindow: true, active: true}).then((tabs) => {
				Taburl=tabs[0].url;
				console.log("active Taburl changed: "+Taburl);
				if(Taburl.match("about:newtab")){
					y=m.popupinfo;
					z=JSON.parse(y);
					//console.log("bgg background script received popup data so storing in y "+ y);
					console.log("if Taburl is newtab ignore retrieving and stored in fullurl "+z[0]);   // here we r storing in previous url not in current url
					sessionStorage.setItem(z[0],m.popupinfo);
				} 
				else{
					console.log("if Taburl is already opened tab so retrieved from Taburl: "+Taburl+" not in z[0]: "+z[0]);
					y=sessionStorage.getItem(Taburl);
				}
			});
		}
		
		// Update content when a new tab becomes active.
		browser.tabs.onActivated.addListener(updateContent2);
*/

browser.tabs.query({ currentWindow: true, active: true }).then((tabs) => {

	var urlPort = browser.runtime.connect({ name: "urlport-from-popup" });

	urlPort.postMessage({ "request_url": "url" });

	urlPort.onMessage.addListener(function (m) {
		host = m.url_response;
		fullurl = m.fullurl_response;
		console.log("Message from the background script to popup: message.url: " + host + " :or m.fullurl: " + fullurl + " :AND tabs[0].url(active url here): " + tabs[0].url);

		var popupPort = browser.runtime.connect({ name: "popupport-from-popup" });

		popupPort.postMessage({ "request_popupdata": "popupdata" });

		popupPort.onMessage.addListener(function (m) {
			console.log("Message from the background script to popup: m.popupdata " + m.popupdata);


			var data = "";
			if (tabs[0].url.match(fullurl)) {
				console.log("new tab or same tab so display and store in tabs[0].url" + tabs[0].url);
				//sessionStorage.setItem(tabs[0].url,m.popupdata);
				localStorage.setItem(tabs[0].url, m.popupdata);
				console.log(m)
				data = JSON.parse(m.popupdata);
				console.log("in if data[0]: " + data[0]);
			}
			else {
				console.log("previosly loaded tab i.e retrieve from tabs[0].url" + tabs[0].url);
				//data=sessionStorage.getItem(tabs[0].url);
				//data=JSON.parse(data);
				//console.log("in else data[0]: "+data[0]);
				data = localStorage.getItem(tabs[0].url);
				data = JSON.parse(data);
				// console.log("in else data[0]: " + data[0]);
			}

			hostheader = data[0];
			msg7 = data[1];  //dyn hid ifr
			msg8 = data[2]; //dyn sc req
			msg3 = data[3];  //tag encode
			msg4 = data[4]; //meta
			msg5 = data[5]; //ext domain
			msg6 = data[6]; //trackers

			if (hostheader) {

				let san = DOMPurify.sanitize("URL: " + hostheader)
				console.log(san)
				$('#cdac_domain').html($.parseHTML(san));
			}
			if (msg7) {
				let san1 = DOMPurify.sanitize(msg7)
				$('#cdac_one').html($.parseHTML(san1));	//REVIEW 
				let san2 = DOMPurify.sanitize("<div>Hidden iframe(s) Redirections</div>")
				$('#cdac_menuone').html($.parseHTML(san2));
				let san3 = DOMPurify.sanitize("<div class='count'>  </div>")
				$('#topCountone').html($.parseHTML(san3));
			}
			else {
				let san1 = DOMPurify.sanitize("No Hidden iframes")
				$('#cdac_one').html($.parseHTML(san1));
				let san2 = DOMPurify.sanitize("<div>Hidden iframe(s) Redirections</div>")
				$('#cdac_menuone').html($.parseHTML(san2));
				let san3 = DOMPurify.sanitize("<div ></div>")
				$('#topCountone').html($.parseHTML(san3));
			}
			if (msg8) {
				let san1 = DOMPurify.sanitize(msg8)
				$('#cdac_two').html($.parseHTML(san1));
				let san2 = DOMPurify.sanitize("<div>UnAuthorized Redirections</div>")
				$('#cdac_menutwo').html($.parseHTML(san2));
				let san3 = DOMPurify.sanitize("<div class='count'>  </div>")
				$('#topCounttwo').html(san3);
			}
			else {
				let san1 = DOMPurify.sanitize("No UnAuthorized Redirections")
				$('#cdac_two').html($.parseHTML(san1));
				let san2 = DOMPurify.sanitize("<div>UnAuthorized Redirections</div>")
				$('#cdac_menutwo').html($.parseHTML(san2));
				let san3 = DOMPurify.sanitize("<div>  </div>")
				$('#topCounttwo').html(san3);
			}
			if (msg3) {
				let san1 = DOMPurify.sanitize(msg3)
				$('#cdac_three').html($.parseHTML(san1));
				let san2 = DOMPurify.sanitize("<div>Encoded JavaScript</div>")
				$('#cdac_menuthree').html($.parseHTML(san2));
				let san3 = DOMPurify.sanitize("<div class='count'>  </div>")
				$('#topCountthree').html($.parseHTML(san3));
			}
			else {
				let san1 = DOMPurify.sanitize("No Encoded JavaScript")
				$('#cdac_three').html($.parseHTML(san1));
				let san2 = DOMPurify.sanitize("<div>Encoded JavaScript</div>")
				$('#cdac_menuthree').html($.parseHTML(san2));
				let san3 = DOMPurify.sanitize("<div></div>")
				$('#topCountthree').html($.parseHTML(san3));
				
			}
			if (msg4) {
				let san1 = DOMPurify.sanitize("<div style='color:red'>" + msg4 + "</div>" + "<br><br>" + host + " links to the following External Domains:<br>" + msg5)
				$('#cdac_four').html($.parseHTML(san1));
				let san2= DOMPurify.sanitize("<div>External Domain Requests</div>")
				$('#cdac_menufour').html($.parseHTML(san2));
				let san3 = DOMPurify.sanitize("<div class='count'>  </div>")
				$('#topCountfour').html($.parseHTML(san3));
			}
			else if (msg5) {
		
				let san1 = DOMPurify.sanitize(host + " links to the following External Domains:<br>" + msg5)
				$('#cdac_four').html($.parseHTML(san1));
				let san2 = DOMPurify.sanitize("<div>External Domain Requests</div>")
				$('#cdac_menufour').html($.parseHTML(san2));
				let san3 = DOMPurify.sanitize("<div class='county'>  </div>")
				$('#topCountfour').html($.parseHTML(san3));
			}
			else {
				let san1 = DOMPurify.sanitize("No External Domain Requests");
				$('#cdac_four').html($.parseHTML(san1));
				let san2 = DOMPurify.sanitize("<div>External Domain Requests</div>")
				$('#cdac_menufour').html($.parseHTML(san2));
				let san3 = DOMPurify.sanitize("<div></div>")
				$('#topCountfour').html($.parseHTML(san3));
			}
				
			if (msg6) {
				let san1 = DOMPurify.sanitize(msg6)
				$('#cdac_five').html($.parseHTML(san1));
				let san2 = DOMPurify.sanitize("<div>Trackers</div>")
				$('#cdac_menufive').html($.parseHTML(san2));
				let san3 = DOMPurify.sanitize("<div class='county'>  </div>")
				$('#topCountfive').html($.parseHTML(san3));
			} else {
				let san1 = DOMPurify.sanitize("No Trackers found")
				$('#cdac_five').html($.parseHTML(san1));
				let san2 = DOMPurify.sanitize("<div>Trackers</div>")
				$('#cdac_menufive').html($.parseHTML(san2));
				let san3 = DOMPurify.sanitize("<div></div>")
				$('#topCountfive').html($.parseHTML(san3));


			}

		});


	});

});










