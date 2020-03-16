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
				console.log("in else data[0]: " + data[0]);
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
				$('#cdac_two').html($.parseHTML(msg8));
				$('#cdac_menutwo').html($.parseHTML("<div>UnAuthorized Redirections</div>"));
				$('#topCounttwo').html("<div class='count'>  </div>");
			}
			else {
				$('#cdac_two').html($.parseHTML("No UnAuthorized Redirections"));
				$('#cdac_menutwo').html($.parseHTML("<div>UnAuthorized Redirections</div>"));
				$('#topCounttwo').html($.parseHTML("<div ></div>"));
			}
			if (msg3) {
				$('#cdac_three').html(msg3);
				$('#cdac_menuthree').html($.parseHTML("<div>Encoded JavaScript</div>"));
				$('#topCountthree').html($.parseHTML("<div class='count'>  </div>"));
			}
			else {
				$('#cdac_three').html($.parseHTML("No Encoded JavaScript"));
				$('#cdac_menuthree').html($.parseHTML("<div>Encoded JavaScript</div>"));
				$('#topCountthree').html($.parseHTML("<div ></div>"));
			}
			if (msg4) {
				$('#cdac_four').html($.parseHTML("<div style='color:red'>" + msg4 + "</div>" + "<br><br>" + host + " links to the following External Domains:<br>" + msg5));
				$('#cdac_menufour').html($.parseHTML("<div>External Domain Requests</div>"));
				$('#topCountfour').html($.parseHTML("<div class='count'>  </div>"));
			}
			else if (msg5) {
				// $('#cdac_four').html($.parseHTML(host + " links to the following External Domains:<br>" + msg5));
				// $('#cdac_menufour').html($.parseHTML("<div>External Domain Requests</div>"));
				// $('#topCountfour').html($.parseHTML("<div class='county'>  </div>"));

				var san1 = DOMPurify.sanitize(host + " links to the following External Domains:<br>" + msg5)
				console.log($.parseHTML(san1))
				$('#cdac_four').html($.parseHTML(san1));
				var san2 = DOMPurify.sanitize("<div>External Domain Requests</div>")
				console.log($.parseHTML(san2))
				$('#cdac_menufour').html($.parseHTML(san2));
				var san3 = DOMPurify.sanitize("<div class='county'>  </div>")
				console.log($.parseHTML(san3))
				$('#topCountfour').html($.parseHTML(san3));
			}
			else {
				$('#cdac_four').html($.parseHTML("No External Domain Requests"));
				$('#cdac_menufour').html($.parseHTML("<div>External Domain Requests</div>"));
				$('#topCountfour').html($.parseHTML("<div ></div>"));
			}
			if (msg6) {
				$('#cdac_five').html($.parseHTML(msg6));
				$('#cdac_menufive').html($.parseHTML("<div>Trackers</div>"));
				$('#topCountfive').html($.parseHTML("<div class='county'>  </div>"));
			} else {
				$('#cdac_five').html($.parseHTML("No Trackers found"));
				$('#cdac_menufive').html($.parseHTML("<div>Trackers</div>"));
				$('#topCountfive').html($.parseHTML("<div ></div>"));
			}

		});


	});

});










