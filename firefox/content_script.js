/*
Copyright (c) 2009-2010 C-DAC
All Rights Reserved

Developed by:
        C-DAC Hyderabad
    
Project:
        MPS-II

Module Name:
        dD.js
************ Module for
i. accesing user requested webpage and monitor for vulnerable tags & javascript injections 
ii. injecting a script into webpage to acess javascript functions & its arguments  and check for maliciousness  ***********************************************************************************************/

//To get full URL
var fullurl=window.location.href;
//only proto
var proto=location.protocol;

var score_ifd=0,score_w=0,score_ev=0,score_sh=0,score_req=0,score=0,shellp1=[],docWrite1=[],re1=[],req1=[],reqq1=[],alertt2=[],alertt3=[];//create global arrays to store the parameters of dynamic functions

/*
 * Calling handy injection function for injecting the variables into the webpage
 * @returns {undefined}
 */
addJS_Node ("var count=0,shellp=[],docWrite=[],re=[],req=[],reqq=[],alert2=[],alert3=[],al2='';");// create local arrays

/*
 * Creating hook to document.create and document.write for obtaining the 
 * parameters of the respective methods
 * @returns {undefined}
 */
function LogDocCreateElement ()
{ 
    var host1=document.location.hostname;

    try{
        var oldDocumentCreateElement = document.createElement;   
	document.createElement = function(tagName)
	{
            var elem = oldDocumentCreateElement.apply (document, arguments); 

            if (tagName === "script"){
                getScriptAttributes (elem, tagName); //Identifying the attributes of suspicious tags
            }
            if (tagName === "iframe"){
                getScriptAttributes (elem, tagName);
            }
            if (tagName === "a"){
                getScriptAttributes (elem, tagName);
            }
            if (tagName === "link"){
                getScriptAttributes (elem, tagName);
            }
	return elem;
	}

        //Creating hook to document.write to obtain the parameters of the method
	var oldDocumentWrite = document.write; 
	document.write      = function (str) 
	{   
            var host1=document.location.hostname;     
            var elem1 = oldDocumentWrite.apply (document,arguments); 
            /*
             * Filling the content of doc.write into the docWrite array variable
             * which is already injected into the webpage
             */
            docWrite.push(str);
            if(str.length > 20){
                encodeJs(str); // verifying the existance of encoded JS
                nonPrint(str); //verifying the presence of shellcode;
            }
            
            /*
             * Checking whether any tags are created through doc.write content
             * Uses DOM parser for converting string into DOM format
             * @type DOMParser
             */
            var parser = new DOMParser();
            var div = parser.parseFromString(str, "text/html");

            //Verifying the presence of suspicious tags
            var tagifr=div.getElementsByTagName("iframe");
            var tagsc=div.getElementsByTagName("script");
            //iframe properties
            if(tagifr.length>0){
                /* ----  Retrieving the attributes of the iframe tag ---- */    
                for(var j=0;j<tagifr.length;j++)
                {

                    if(tagifr[j].src){
                        var x,y,styl,src,ext;
                        x=tagifr[j].height;        // height
                        y=tagifr[j].width;         // width
                        styl=tagifr[j].style;
                        src=tagifr[j].src;
                        if(x || y || styl)
                        {
                            if(x)
                            {
                                if(x.match(/px/gi))
                                {
                                    ext = x.substring(0, x.length-2);
                                    if(ext < 3)
                                    {
                                        domainmatch(src);
                                    }
                                }

                                else if(x<3)
                                {
                                    domainmatch(src);
                                }
                            }
                            else if(y) 
                            {
                                if(y.match(/px/gi))
                                {
                                    ext = y.substring(0, y.length-2);
                                    if(ext < 3)
                                    {
                                        domainmatch(src);	
                                    }
                                }
                                else if(y<3)
                                {
                                    domainmatch(src);
                                }
                            }
                            else if(styl)
                            {
                                var str,d=0;
                                if(String(styl).match(/;/))
                                {
                                    var arr_str = String(styl).split(";");
                                    while(d < arr_str.length){
                                        str = arr_str[d].split(":");
                                        if(str[0] === "height" || str[0] === "width"){ 
                                            var ext = str[1].substring(0, str[1].length-2);
                                            if(ext < 3){
                                                domainmatch(src);
                                            }
                                        }
                                        else if(str[0] === "left" || str[0] === "right" || str[0] === "top" || str[0] === "bottom"){ 
                                        var ext = str[1].substring(0, str[1].length-2);
                                            if(ext < -99){
                                                domainmatch(src);
                                            }
                                        }
                                        else if(str[0] === "visibility" || str[0] === "display"){
                                                if(str[1].match(/hidden/gi) || str[1].match(/none/gi)){
                                                    domainmatch(src);
                                                }
                                        }
                                        d++;
                                    }
                                }
                                else if(String(styl).match(/:/))
                                {
                                    str = String(styl).split(":");
                                    if(str[0] === "visibility" || str[0] === "display"){
                                        if(str[1].match(/hidden/gi) || str[1].match(/none/gi)){
                                                domainmatch(src);
                                        }
                                    }
                                }							

                            }

                        }

                    }

                }
            }
            /*
             * Monitoring the Script tag creating through doc.write
             */
            if(tagsc.length>0)
            {
                for(var m=0;m<tagsc.length;m++)
                {
                    if(tagsc[m].src)
                    {
                        var flag1=0,srcc1, srcc, src2, patt2=/.js/g ;
                        var TLDS = new Array(/com/gi, /net/gi, /in/gi);
                        var myvar = tagsc[m].src;
                        srcc1=myvar.replace('http://','').replace('https://','').replace('www.','').split(/[/?#]/)[0];

                        var parts = srcc1.split('.');
                        var srcc = parts.slice(-1).join('.');
// filtered com/in/net sites to reduce false positives
                  /*      for(var k=0;k<TLDS.length;k++)
                        {
                            if(srcc.match(TLDS[k]) !== null){
                                flag1=1;
                            }
                        }*/ // commented bcoz anyway we r cross verifying with gsb    
                        /*
                         * Finding Redirectors in Script tag if the domain name
                         * does not belongs to TLDS array patterns
                         */
if(host1.match(srcc1) === null && srcc1.match(host1) === null && flag1 === 0 && !re.length){		
//if((host1.match(srcc1) === null && myvar.match(host1) === null) && tagsc[m].src.match(host1) === null && flag1 === 0 && !re.length){														
                            var talert1="";
                            if(tagsc[m].src.match(patt2) !== null){
                                if(tagsc[m].src.match("\\.js.php")!==null  || tagsc[m].src.match("\\.php.js")!==null || tagsc[m].src.match("jquery.min.php")!==null){
                                    src2='Evil URL(s) ::<br> '+srcc1;
                                    talert1 += "\n"+srcc1;
                                    re.push('Threat::  Malicious JS Redirector<br>'+src2);
                                    req.push('<b>Malicious JS:Redirector</b><br>'+src2);
                                }
                            }
                            //checking for non js(php/asp) pattern
                            else {
                                if(tagsc[m].src.match("\\.php")!==null ){
                                    src2='Evil URL is ::: '+srcc1;
                                    talert1 += "\n"+srcc1;
                                    re.push('Threat::  Malicious JS Redirector<br>'+src2);
                                    req.push('<b>Malicious JS Redirector</b><br>'+src2);
                                }
                            }
                            sessionStorage.setItem("alertsc1", JSON.stringify(talert1));
                        }
                    }
                }
            }//if
            return elem1;      
	}
    }//try
    catch(err)
    {
        //alert("error");
    }
    
    /*
     * Detecting Encoded JavaScript in the content of the doc.write
     * @param {type} text
     * @returns {undefined}
     */
    function encodeJs(text)
    {

        var scriptstring = text.replace(/(\r\n|\n|\r)/gm,""); //convert the innerHTML to one line, easier to match               
        if(scriptstring.length>250){
         /*dividing into lines, then words, then word size*/
            var words;
            var lines = scriptstring.split(";");                
            for(var m = 0; (lines !== null) && (m<lines.length); m++) {
                words = lines[m].split(" ");                
                for(var k = 0; (words !== null) && (k<words.length); k++) {
                    if(words[k].length > 5000){
                        shellp.push("Wdyn: 1 ");
                    }			
                }
            }
            
            // pecentage of digits in each script 			
            var indScriptLength = scriptstring.length;
            var indNumLength = scriptstring.replace(/\D/g, '').length;
            var inddigitdensity=((indNumLength*100)/indScriptLength);
            if(((indNumLength*100)/indScriptLength) > 30){
                shellp.push("IDDdyn: 1 ");
            }
            
            /* n-gram for individual script*/
            var specialChars = new Array (/%/g,/$/g,/</g,/>/g,/@/g,/!/g,/#/g,/^/g,/&/g,/\*/g,/\(/g,/\)/g,/_/g,/\+/g,/\[/g,/\]/g,/\{/g,/\}/g,/\?/g,/:/g,/;/g,/'/g,/"/g,/,/g,/\./g,/\//g,/~/g,/\`/g,/-/g,/=/g,/\\/g);
            var totalnumbersc=0, encodenumbers=0, encodedanddigitnumbers=0;
            for(var n = 0; n < specialChars.length;n++){
                if(scriptstring.match(specialChars[n])){
                    totalnumbersc +=scriptstring.match(specialChars[n]).length;
                    if(n==0 || n== 4 || n == 5 || n==12 || n ==22 || n==23)
                    {
                        encodenumbers +=scriptstring.match(specialChars[n]).length;
                    }
                }
            }
            encodedanddigitnumbers=(indNumLength) + (encodenumbers);
            indspdensity=(encodedanddigitnumbers*100)/scriptstring.length;
            if(indspdensity > 50){
//                    shellp.push("ISPdyn: 1 ");
                var scriptstringN = scriptstring.replace(/[^a-zA-Z]/g,'');
                if((scriptstringN.match(/unescape/g) || scriptstringN.match(/fromCharCode/g)) && !alert3){
                    alert3.push("Threat:: Encoded JavaScript Malware</n>");
                    shellp.push("Threat:: Encoded JavaScript Malware"+"<br>"+"Malicious content is:: " +scriptstring);
                }
            }

        }
    }
    
    /*
     * Detecting Non printable characters or shellcode in the content of doc.write
     * @param {type} text
     * @returns {undefined}
     */
    function nonPrint(text)
    {
        var pat=/[^\x00-\x80]+/g;//Regex for checking non-printable characters
        if(pat.test(text))
        {
            shellp.push("Non Printable characters are present\n");
            shellp.push(text);
        }
        var r = new RegExp("^[a-f0-9]+$", 'i');//regex for identifying consecutive Hexadecimal characters in a string
        if(r.test(text))
        {
            shellp.push("consecutive block of hexadecimal characters\n");
            shellp.push(text);
        }
    }
    
    /*
     * Cross verify the source of the hidden iframe property with the host name 
     * of the original URL and if it does not belongs to the same origin then 
     * alerts the user 
     * @param {type} src
     * @returns {undefined}
     */
    function domainmatch(src)
    {
          /*  //whitelist, 3rd party advertising sites and tracking sites*/

        var whitelist = new Array (/about:blank/gi,/blank.html/gi,/wp/gi,/*/google/gi ,*//facebook/gi ,/youtube/gi ,/quantserve/gi ,/vizury/gi , /Media/gi , /33across/gi , /AOLAdvertising/gi , /AWeber/gi , /Acerno/gi , /AcxiomRelevance-X/gi , /AdLegend/gi , /AdMeld/gi , /AdNexus/gi , /AdSafe/gi , /AdShuffle/gi , /AdTech/gi , /Adap.TV/gi , /AdaptiveBlueSmartlinks/gi , /AdaraMedia/gi , /Adblade/gi , /Adbrite/gi , /Adcentric/gi , /Adconion/gi , /AddThis/gi , /AddToAny/gi , /Adify/gi , /Adition/gi , /Adjuggler/gi , /AdnetInteractive/gi , /Adnetik/gi , /Adreactor/gi , /Adrolays/gi , /Adroll/gi , /Advertise.com/gi , /Advertising.com/gi , /Adxpose/gi , /Adzerk/gi ,/affinity/gi , /AggregateKnowledge/gi , /AlexaMetrics/gi , /AlmondNet/gi , /Aperture/gi , /BTBuckets/gi , /Baynote/gi , /Bing/gi , /Bizo/gi , /BlogRollr/gi , /Blogads/gi , /BlueKai/gi , /BlueLithium/gi , /BrandReach/gi , /BrightTag/gi , /Brightcove/gi , /Brightroll/gi , /Brilig/gi , /BurstMedia/gi , /BuySellAds/gi , /CNETTracking/gi , /CPXInteractive/gi , /CasaleMedia/gi , /CedexisRadar/gi , /CertonaResonance/gi , /Chango/gi , /ChannelAdvisor/gi , /ChartBeat/gi , /Checkm8/gi , /Chitika/gi , /ChoiceStream/gi , /ClearSaleing/gi , /ClickDensity/gi , /Clickability/gi , /Clicksor/gi , /Clicktale/gi , /Clicky/gi , /CognitiveMatch/gi , /Collarity/gi , /CollectiveMedia/gi , /Comscore Beacon/gi , /Connextra/gi , /ContextWeb/gi , /CoreMetrics/gi , /CrazyEgg/gi , /Criteo/gi , /Cross PixelMedia/gi , /CrowdScience/gi , /DC Storm/gi , /Dapper/gi , /DedicatedMedia/gi , /Demandbase/gi , /Demdex/gi , /DeveloperMedia/gi , /Didit/gi , /DiggWidget/gi , /DiggThis/gi , /Disqus/gi , /Dotomi/gi , /DoubleVerify/gi , /Doubleclick/gi , /DynamicLogic/gi , /EffectiveMeasure/gi , /Eloqua/gi , /Ensighten/gi , /EpicMarketplace/gi , /Etology/gi , /Evidon/gi , /Exponential/gi , /EyeWonder/gi , /Facebook Beacon/gi , /FacebookConnect/gi , /FederatedMedia/gi , /Feedjit/gi , /FetchBack/gi , /Flashtalking/gi , /ForeseeResults/gi , /FoxAudienceNetwork/gi , /FreeWheel/gi , /GetSatisfaction/gi , /Gigya/gi , /GlamMedia/gi , /Gomez/gi ,  /GoogleAdsense/gi , /GoogleAdwordsConversion/gi , /GoogleAnalytics/gi , /GoogleFriendConnect/gi , /GoogleWebsiteOptimizer/gi , /GoogleWidgets/gi , /Gravatar/gi , /Gravity/gi , /Hellobar/gi , /HitTail/gi , /Hurra/gi , /InfoLinks/gi , /Inkfrog/gi , /InsightExpress/gi , /InterClick/gi , /InviteMedia/gi , /Iovation/gi , /KissMetrics/gi , /KonteraContentLink/gi , /KruxDigital/gi , /LeadLander/gi , /Leadformix/gi , /Leadsius/gi , /LifeStreet Media/gi , /Lijit/gi , /LinkedIn/gi , /Linkshare/gi , /LiveInternet/gi , /LivePerson/gi , /Lotame/gi , /LucidMedia/gi , /LyrisClicktracks/gi , /MAGNETIC/gi , /MSNAds/gi , /MarinSoftware/gi , /MarketGID/gi , /Marketo/gi , /MaxPointInteractive/gi , /Maxymizer/gi , /MediaInnovationGroup/gi , /Media6Degrees/gi , /MediaMath/gi , /MediaMind/gi , /MediaPlex/gi , /Meebo/gi , /Mercent/gi , /Meteor/gi , /MicrosoftAnalytics/gi , /MicrosoftAtlas/gi , /MindsetMedia/gi , /Mint/gi , /Mixpanel/gi , /Monetate/gi , /MyBlogLog/gi , /NDN/gi , /Navegg/gi , /NetMining/gi , /NetShelter/gi , /NetratingsSiteCensus/gi , /NewRelic/gi , /NewsRight/gi , /NextAction/gi , /Nuggad/gi , /Omniture/gi , /OpenAds/gi , /OpenX/gi , /Optimizely/gi , /Optimost/gi , /OutBrain/gi , /OwnerIQ/gi , /PO.ST/gi , /Parse.ly/gi , /Piwik/gi , /PointRoll/gi , /PostRank/gi , /Pubmatic/gi , /Qualaroo/gi , /Quantcast/gi , /QuigoAdsonar/gi , /RadiumOne/gi , /RapLeaf/gi , /RealMedia/gi , /Reinvigorate/gi , /Relestar/gi , /RevenueScience/gi , /RevenueMantra/gi , /RightMedia/gi , /RocketFuel/gi , /Rubicon/gi , /RubiconProject/gi , /SafeCount/gi , /Salesforce/gi , /ShareThis/gi , /SiteMeter/gi , /SiteScout/gi , /SkimLinks/gi , /Smart Adserver/gi , /Snaps/gi , /Snoobi/gi , /Specific Meida/gi , /SpecificClick/gi , /Sphere/gi , /StatCounter/gi , /TARGUSinfoAdAdvisor/gi , /Taboola/gi , /Tacoda/gi , /TeaLeaf/gi , /Tealium/gi , /Technorati/gi , /TechnoratiMedia/gi , /Tellapart/gi , /Teracent/gi , /TestandTarget/gi , /TidalTV/gi , /TorbitInsight/gi , /TradeDoubler/gi , /TravelAdvertising/gi , /TremorVideo/gi , /TribalFusion/gi , /Tumri/gi , /Turn/gi , /TweetMeme/gi , /TwitterBadge/gi , /TyntTracer/gi , /Typekit/gi , /UnderdogMedia/gi , /UndertoneNetworks/gi , /Unica/gi , /ValueClick/gi , /ValuedOpinions/gi , /VibrantAds/gi , /VigLink/gi , /VisualSciences/gi , /VisualWebsiteOptimizer/gi , /VisualRevenue/gi , /ViziSense/gi , /Vizu/gi , /Vizury/gi ,/WebAds/gi , /Webtrends/gi , /Whos.amung.us/gi , /Wibiya/gi , /Woopra/gi , /WordpressStats/gi , /WorldNow/gi , /XGraph/gi , /Yadro/gi , /YahooBuzz/gi , /YahooWebAnalytics/gi , /YuMeNetworks/gi , /Zango/gi , /Zedo/gi , /Zemanta/gi , /e-planning/gi , /eXTReMe Tracking/gi , /eXelate/gi , /etracker/gi , /iPerception/gi, /bs.serving-sys.com/gi, /hitwebcounter/gi, /freecounterstat/gi, /yieldmanager/gi, /adnxs/gi, /scorecard/gi);
        var flag=0, src1, dalert2="", srcc1;	
        al2+=reqq;
        srcc1=src.replace('http://','').replace('https://','').replace('www.','').split(/[/?#]/)[0];
        if((host1.match(srcc1) === null && src.match(host1) === null) && al2.match(srcc1) ===null){
            for(var m=0;m<whitelist.length;m++)
            {
                if(srcc1.match(whitelist[m]) !== null){
                        flag=1;
                        return;
                }
            }
            if(flag===0 && !al2){
                dalert2 += "\n"+srcc1;
                alert2.push("\n"+srcc1);
                reqq.push("<b>JS:Hidden Iframe<br>URL(s)::</b><br>==>"+src);

            }
            else if(flag===0 && al2 && al2.match(srcc1) === null){
                alert2.push("\n"+srcc1);
                reqq.push("<br>==>"+src);
                dalert2 += "\n"+srcc1;
            }
            sessionStorage.setItem("alertif1", dalert2);
        }
    }

    shellp1=shellp;
    docWrite1=docWrite;
    re1=re;
    req1=req;
    reqq1=reqq;
    alertt2=alert2;
    alertt3=alert3;
}


/*
 * Analyzing the content of document.createElement function
 * @param {type} elem : Properties of tags present in the contents
 * @param {type} tagName : Name of the tag present in the contents
 * @param {type} timerIntVar 
 * @returns {undefined}
 */
function getScriptAttributes (elem, tagName, timerIntVar) 
{
    var host1=document.location.hostname;     
/*--- Because the tags won't be set for some while, we need
    to poll for when they are added.
---Tracking the attributes which can redirect to malcious web page---*/
    if (elem.src && elem.src !== "/blank.html" && elem.src !=="about:blank") 
    {

        doneWaiting ();
        var flag1=0, src2, srcc1, srcc, patt2=/.js/g ;
        var TLDS = new Array(/com/gi, /net/gi, /in/gi);
        var myvar = elem.src;
        srcc1=myvar.replace('http://','').replace('https://','').replace('www.','').split(/[/?#]/)[0];

        var parts = srcc1.split('.');
        srcc = parts.slice(-1).join('.');
     /*   for(var m=0;m<TLDS.length;m++)
        {
                if(srcc.match(TLDS[m]) !== null){
                        flag1=1;
                }
        }*/ //  anyway cross verifying with gsb
        
        if(tagName === "iframe")
        {
            var x,y,src,ext;
            x=elem.height;        // height
            y=elem.width;         // width
            stylh=elem.style.height;      //style
            stylw=elem.style.width;
            styll=elem.style.left;      //style
            stylr=elem.style.right;
            stylt=elem.style.top;      //style
            stylb=elem.style.bottom;
            stylv=elem.style.visibility;
            styld=elem.style.display;
            src=elem.src;
            if(x || y || stylh || stylw || stylv || styld)
            {
                if(x)
                {
                        if(x.match(/px/gi))
                        {
                                var ext = x.substring(0, x.length-2);
                                if(ext < 3)
                                {
                                        domainmatch1(src);
                                }
                        }	                                    
                        else if(x<3)
                        {
                                domainmatch1(src);
                        }
                }
                if(y) 
                {
                        if(y.match(/px/gi))
                        {
                                var ext = y.substring(0, y.length-2);
                                if(ext < 3)
                                {
                                        domainmatch1(src);	
                                }
                        }
                        else if(y<3)
                        {
                                domainmatch1(src);
                        }
                }
                if(stylh) 
                {
                        if(stylh.match(/px/gi))
                        {
                                var ext = stylh.substring(0, stylh.length-2);
                                if(ext < 3)
                                {
                                        domainmatch1(src);	
                                }
                        }
                        else if(stylh<3)
                        {
                                domainmatch1(src);
                        }
                }
                if(stylw) 
                {
                        if(stylw.match(/px/gi))
                        {
                                var ext = stylw.substring(0, stylw.length-2);
                                if(ext < 3)
                                {
                                        domainmatch1(src);	
                                }
                        }
                        else if(stylw<3)
                        {
                                domainmatch1(src);
                        }
                }
                if(stylv) 
                {
                        if(stylv.match(/hidden/gi))
                        {                        		
                                domainmatch1(src);	
                        }

                }
                if(styld) 
                {
                        if(styld.match(/none/gi))
                        {                        		
                                domainmatch1(src);	
                        }
                }
            }
            if(styll || stylr || stylt || stylb)
            {
                    if(styll){
                            var ext = styll.substring(0, styll.length-2);
                            if(ext < -99)
                            {
                                    domainmatch1(src);	
                            }
                    }
                    if(stylr){
                            var ext = stylr.substring(0, stylr.length-2);
                            if(ext < -99)
                            {
                                    domainmatch1(src);	
                            }
                    }
                    if(stylt){
                            var ext = stylt.substring(0, stylt.length-2);
                            if(ext < -99)
                            {
                                    domainmatch1(src);	
                            }
                    }
                    if(stylb){
                            var ext = stylb.substring(0, stylb.length-2);
                            if(ext < -99)
                            {
                                    domainmatch1(src);	
                            }
                    }
            }
        }  //iframe  
	else if(elem.src.match(host1) === null && host1.match(srcc1) === null && flag1 === 0 && !re.length){
            var myvar = elem.src,ttalert1="";
            var s1=myvar.replace('http://','').replace('https://','').replace('www.','').split(/[/?#]/)[0];

            if(elem.src.match(patt2) !== null){

                if(elem.src.match("\\.js.php")!==null  || elem.src.match("\\.php.js")!==null || elem.src.match("jquery.min.php")!==null){
                    src2='Evil URL(s) ::: '+elem.src;
                    ttalert1 += "\n"+elem.src;
                    re.push('Threat::  Malicious JS Redirector<br>'+src2);
                    req.push('<b>Malicious JS Redirector</b><br>'+src2);
                }
            }
            //checking for non js(php/asp) pattern
            else {
                if(elem.src.match("\\.php")!==null ){//console.log("dcs: "+s1);
                    src2='Evil URL is ::: '+s1;
                    ttalert1 += "\n"+elem.src;
                    re.push('Threat::  Malicious JS Redirector<br>'+src2);
                    req.push('<b>Malicious JS Redirector</b><br>'+src2);
                }
            }
            sessionStorage.setItem("alertsc2", JSON.stringify(ttalert1));
        }
    }
    else
    {
        if ( ! timerIntVar) //Setting the time interval to wait for the tags untill they are well-set
        {
            var timerIntVar = setInterval 
            (
            function () 
            {
                getScriptAttributes (elem, tagName,timerIntVar);                    
            },
            50
            );            
        }        
    }    
    function doneWaiting () //clear the time interval when the tags are set
    {
            if (timerIntVar) 
            {
                    clearInterval (timerIntVar);
            }       
    }
    function domainmatch1(src){
            //whitelist, 3rd party advertising sites and tracking sites
            var dots=src.match(/\./g);
            if(src === null || !dots){
                    return;
            }

            var whitelist = new Array (/about:blank/gi,/blank.html/gi,/wp/gi,/*/google/gi,*//facebook/gi ,/youtube/gi ,/quantserve/gi ,/vizury/gi , /Media/gi , /33across/gi , /AOLAdvertising/gi , /AWeber/gi , /Acerno/gi , /AcxiomRelevance-X/gi , /AdLegend/gi , /AdMeld/gi , /AdNexus/gi , /AdSafe/gi , /AdShuffle/gi , /AdTech/gi , /Adap.TV/gi , /AdaptiveBlueSmartlinks/gi , /AdaraMedia/gi , /Adblade/gi , /Adbrite/gi , /Adcentric/gi , /Adconion/gi , /AddThis/gi , /AddToAny/gi , /Adify/gi , /Adition/gi , /Adjuggler/gi , /AdnetInteractive/gi , /Adnetik/gi , /Adreactor/gi , /Adrolays/gi , /Adroll/gi , /Advertise.com/gi , /Advertising.com/gi , /Adxpose/gi , /Adzerk/gi ,/affinity/gi , /AggregateKnowledge/gi , /AlexaMetrics/gi , /AlmondNet/gi , /Aperture/gi , /BTBuckets/gi , /Baynote/gi , /Bing/gi , /Bizo/gi , /BlogRollr/gi , /Blogads/gi , /BlueKai/gi , /BlueLithium/gi , /BrandReach/gi , /BrightTag/gi , /Brightcove/gi , /Brightroll/gi , /Brilig/gi , /BurstMedia/gi , /BuySellAds/gi , /CNETTracking/gi , /CPXInteractive/gi , /CasaleMedia/gi , /CedexisRadar/gi , /CertonaResonance/gi , /Chango/gi , /ChannelAdvisor/gi , /ChartBeat/gi , /Checkm8/gi , /Chitika/gi , /ChoiceStream/gi , /ClearSaleing/gi , /ClickDensity/gi , /Clickability/gi , /Clicksor/gi , /Clicktale/gi , /Clicky/gi , /CognitiveMatch/gi , /Collarity/gi , /CollectiveMedia/gi , /Comscore Beacon/gi , /Connextra/gi , /ContextWeb/gi , /CoreMetrics/gi , /CrazyEgg/gi , /Criteo/gi , /Cross PixelMedia/gi , /CrowdScience/gi , /DC Storm/gi , /Dapper/gi , /DedicatedMedia/gi , /Demandbase/gi , /Demdex/gi , /DeveloperMedia/gi , /Didit/gi , /DiggWidget/gi , /DiggThis/gi , /Disqus/gi , /Dotomi/gi , /DoubleVerify/gi , /Doubleclick/gi , /DynamicLogic/gi , /EffectiveMeasure/gi , /Eloqua/gi , /Ensighten/gi , /EpicMarketplace/gi , /Etology/gi , /Evidon/gi , /Exponential/gi , /EyeWonder/gi , /Facebook Beacon/gi , /FacebookConnect/gi , /FederatedMedia/gi , /Feedjit/gi , /FetchBack/gi , /Flashtalking/gi , /ForeseeResults/gi , /FoxAudienceNetwork/gi , /FreeWheel/gi , /GetSatisfaction/gi , /Gigya/gi , /GlamMedia/gi , /Gomez/gi ,  /GoogleAdsense/gi , /GoogleAdwordsConversion/gi , /GoogleAnalytics/gi , /GoogleFriendConnect/gi , /GoogleWebsiteOptimizer/gi , /GoogleWidgets/gi , /Gravatar/gi , /Gravity/gi , /Hellobar/gi , /HitTail/gi , /Hurra/gi , /InfoLinks/gi , /Inkfrog/gi , /InsightExpress/gi , /InterClick/gi , /InviteMedia/gi , /Iovation/gi , /KissMetrics/gi , /KonteraContentLink/gi , /KruxDigital/gi , /LeadLander/gi , /Leadformix/gi , /Leadsius/gi , /LifeStreet Media/gi , /Lijit/gi , /LinkedIn/gi , /Linkshare/gi , /LiveInternet/gi , /LivePerson/gi , /Lotame/gi , /LucidMedia/gi , /LyrisClicktracks/gi , /MAGNETIC/gi , /MSNAds/gi , /MarinSoftware/gi , /MarketGID/gi , /Marketo/gi , /MaxPointInteractive/gi , /Maxymizer/gi , /MediaInnovationGroup/gi , /Media6Degrees/gi , /MediaMath/gi , /MediaMind/gi , /MediaPlex/gi , /Meebo/gi , /Mercent/gi , /Meteor/gi , /MicrosoftAnalytics/gi , /MicrosoftAtlas/gi , /MindsetMedia/gi , /Mint/gi , /Mixpanel/gi , /Monetate/gi , /MyBlogLog/gi , /NDN/gi , /Navegg/gi , /NetMining/gi , /NetShelter/gi , /NetratingsSiteCensus/gi , /NewRelic/gi , /NewsRight/gi , /NextAction/gi , /Nuggad/gi , /Omniture/gi , /OpenAds/gi , /OpenX/gi , /Optimizely/gi , /Optimost/gi , /OutBrain/gi , /OwnerIQ/gi , /PO.ST/gi , /Parse.ly/gi , /Piwik/gi , /PointRoll/gi , /PostRank/gi , /Pubmatic/gi , /Qualaroo/gi , /Quantcast/gi , /QuigoAdsonar/gi , /RadiumOne/gi , /RapLeaf/gi , /RealMedia/gi , /Reinvigorate/gi , /Relestar/gi , /RevenueScience/gi , /RevenueMantra/gi , /RightMedia/gi , /RocketFuel/gi , /Rubicon/gi , /RubiconProject/gi , /SafeCount/gi , /Salesforce/gi , /ShareThis/gi , /SiteMeter/gi , /SiteScout/gi , /SkimLinks/gi , /Smart Adserver/gi , /Snaps/gi , /Snoobi/gi , /Specific Meida/gi , /SpecificClick/gi , /Sphere/gi , /StatCounter/gi , /TARGUSinfoAdAdvisor/gi , /Taboola/gi , /Tacoda/gi , /TeaLeaf/gi , /Tealium/gi , /Technorati/gi , /TechnoratiMedia/gi , /Tellapart/gi , /Teracent/gi , /TestandTarget/gi , /TidalTV/gi , /TorbitInsight/gi , /TradeDoubler/gi , /TravelAdvertising/gi , /TremorVideo/gi , /TribalFusion/gi , /Tumri/gi , /Turn/gi , /TweetMeme/gi , /TwitterBadge/gi , /TyntTracer/gi , /Typekit/gi , /UnderdogMedia/gi , /UndertoneNetworks/gi , /Unica/gi , /ValueClick/gi , /ValuedOpinions/gi , /VibrantAds/gi , /VigLink/gi , /VisualSciences/gi , /VisualWebsiteOptimizer/gi , /VisualRevenue/gi , /ViziSense/gi , /Vizu/gi , /Vizury/gi ,/WebAds/gi , /Webtrends/gi , /Whos.amung.us/gi , /Wibiya/gi , /Woopra/gi , /WordpressStats/gi , /WorldNow/gi , /XGraph/gi , /Yadro/gi , /YahooBuzz/gi , /YahooWebAnalytics/gi , /YuMeNetworks/gi , /Zango/gi , /Zedo/gi , /Zemanta/gi , /e-planning/gi , /eXTReMe Tracking/gi , /eXelate/gi , /etracker/gi , /iPerception/gi, /bs.serving-sys.com/gi, /hitwebcounter/gi, /freecounterstat/gi, /yieldmanager/gi, /adnxs/gi, /scorecard/gi);
            var flag=0, ddalert2="",srcc1;
            al2+=reqq;
            srcc1=src.replace('http://','').replace('https://','').replace('www.','').split(/[/?#]/)[0];
            if((host1.match(srcc1) === null && src.match(host1) === null) && al2.match(srcc1) ===null){

                    for(var m=0;m<whitelist.length;m++)
                    {
                            if(srcc1.match(whitelist[m]) !== null){//alert("alert");
                                    flag=1;
                                    return;
                            }
                    }
                    if(flag===0 && !al2){
                            alert2.push("\n"+srcc1);
                            ddalert2 += "\n"+srcc1;
                            reqq.push("<b>JS:Hidden Iframe<br>URL(s)::</b><br>==>"+src);
                    }
                    else if(flag===0 && al2 && al2.match(srcc1) === null){
                            alert2.push("\n"+srcc1);
                            ddalert2 += "\n"+srcc1;
                            reqq.push("<br>==>"+src);	
                    }
                    sessionStorage.setItem("alertif2",ddalert2);
            }
    }    
}

//---Injecting the above methods to the web page 
addJS_Node (getScriptAttributes.toString());
//---Injecting the above method to the web page
addJS_Node (null, null, LogDocCreateElement);
//--- Handy injection function.
function addJS_Node (text, s_URL, funcToRun) {
/*--- This function is for injecting the desired functionality in the web page by creating a script tag */
    var D                                   = window.document;
    var scriptNode                          = D.createElement ('script');
    scriptNode.type                         = "text/javascript";
    if (text){       scriptNode.textContent  = text;}
    if (s_URL){      scriptNode.src          = s_URL;}
    if (funcToRun)  scriptNode.textContent  = '(' + funcToRun.toString() + ')()';
    var targ = D.getElementsByTagName ('head')[0] || D.body || D.documentElement;
    targ.appendChild (scriptNode);
    targ.removeChild (scriptNode);    
}
/* when the page is loaded Send emit all the parameters to addon sciript */
$(document).ready(function(){



/* adding css to alert */

var css =' #cdac_container { font-family: Arial, sans-serif !important; font-size: 12px !important; min-width: 300px !important;max-width: 600px !important; text-align: inherit !important;	background: #e8f9ff !important;	border: solid 5px #B40404 !important;	color: #000 !important; -webkit-border-radius: 5px !important;	border-radius: 5px !important;} #cdac_title { display: inherit !important; font-family: inherit !important; font-size: 14px !important; font-weight: bold !important; 	text-align: left !important; line-height: 1.75em !important; color: #FFF !important; text-shadow: inherit !important; height:inherit !important; width:inherit !important; 	position:static !important; background: #B40404 repeat-x center top !important; border: solid 1px #B40404 !important; border-bottom: solid 1px #B40404 !important; cursor: default !important; padding: 0em !important; margin: 0em !important; float: none !important; } .cdac_inputred { background: none !important; background-color:#E6E6E6 !important; color:#DF3A01 !important; font-weight: bold;} .cdac_inputgreen { background: none !important; background-color: #E6E6E6 !important; color:#298A08 !important; font-weight: bold;} #cdac_content { padding: 1em 1.75em !important; margin: 0em !important; } #cdac_message { padding-left: 48px !important; color: #000 !important; } #cdac_panel { text-align: center !important; margin: 1em 0em 0em 1em !important; } #cdac_prompt { margin: .5em 0em !important; }#cdac_content.confirm { background:16px 16px no-repeat url(cdac18.png) !important;}',


head = document.getElementsByTagName('head')[0],
style = document.createElement('style');

style.type = 'text/css';
if (style.styleSheet){
  style.styleSheet.cssText = css;
} else {
  style.appendChild(document.createTextNode(css));
}

head.appendChild(style);

	var i,ev="",res="",reqs="";var docW="";var reqqs="";var shellps="";var alertts="",encodes="",Head="CDAC's Browser JSGuard Warning";


if (typeof window.re1 != 'undefined') {
//console.log("window.re1 success");
 if( window.re1.length>0)
	{
		for(i=0;i< window.re1.length;i++)
		{
			res+= window.re1[i]+"<br>";
	    		      
		}
		score_req=1;
	}

	if( window.req1.length>0)
	{
		for(i=0;i< window.req1.length;i++)
		{
			reqs+= window.req1[i]+"<br>";		      
		}
		score_req=1;
	}

	if( window.reqq1.length>0)
	{
		for(i=0;i< window.reqq1.length;i++)
		{
			reqqs+= window.reqq1[i]+"<br>";
		}
		score_ifd=1;
	}
	

	if( window.alertt2.length>0)
	{
		for(i=0;i< window.alertt2.length;i++)
		{
			//alertts+= alertt2[i]+"<br>";
			alertts+= window.alertt2[i];
		}
		score_ifd=1;
	}
	if( window.alertt3.length>0)
	{
		for(i=0;i< window.alertt3.length;i++)
		{
			encodes+= window.alertt3[i]+"<br>";
		
		}
		score_ifd=1;
	}
    
	if( window.docWrite1.length>0)
	{
		for(i=0;i< window.docWrite1.length;i++)
		{
			docW+= window.docWrite1[i]+"<br>";
		}
		score_w=1;
	}
	
	if( window.shellp1.length>0)
	{
		for(i=0;i< window.shellp1.length;i++)
		{
			shellps+= window.shellp1[i]+"<br>";
		}
		score_sh=1;
	}
}


else{


	 if( re1.length>0)
	{
		for(i=0;i< re1.length;i++)
		{
			res+= re1[i]+"<br>";
	    		      
		}
		score_req=1;
	}

	if( req1.length>0)
	{
		for(i=0;i< req1.length;i++)
		{
			reqs+= req1[i]+"<br>";		      
		}
		score_req=1;
	}

	if( reqq1.length>0)
	{
		for(i=0;i< reqq1.length;i++)
		{
			reqqs+= reqq1[i]+"<br>";
		}
		score_ifd=1;
	}
	

	if( alertt2.length>0)
	{
		for(i=0;i< alertt2.length;i++)
		{
			//alertts+= alertt2[i]+"<br>";
			alertts+= alertt2[i];
		}
		score_ifd=1;
	}
	if( alertt3.length>0)
	{
		for(i=0;i< alertt3.length;i++)
		{
			encodes+= alertt3[i]+"<br>";
		
		}
		score_ifd=1;
	}
    
	if( docWrite1.length>0)
	{
		for(i=0;i< docWrite1.length;i++)
		{
			docW+= docWrite1[i]+"<br>";
		}
		score_w=1;
	}
	
	if( shellp1.length>0)
	{
		for(i=0;i< shellp1.length;i++)
		{
			shellps+= shellp1[i]+"<br>";
		}
		score_sh=1;
	}
}
	score=score_ifd+score_ev+score_sh+score_w;
   
//whitelistgi , 3rd party advertising sites and tracking sites
var whitelist = new Array (/about:blank/gi,/blank.html/gi,/wp/gi,/javascript:/gi,/*/google/gi ,*//facebook/gi ,/youtube/gi ,/quantserve/gi ,/vizury/gi , /Media/gi , /33across/gi , /AOLAdvertising/gi , /AWeber/gi , /Acerno/gi , /AcxiomRelevance-X/gi , /AdLegend/gi , /AdMeld/gi , /AdNexus/gi , /AdSafe/gi , /AdShuffle/gi , /AdTech/gi , /Adap.TV/gi , /AdaptiveBlueSmartlinks/gi , /AdaraMedia/gi , /Adblade/gi , /Adbrite/gi , /Adcentric/gi , /Adconion/gi , /AddThis/gi , /AddToAny/gi , /Adify/gi , /Adition/gi , /Adjuggler/gi , /AdnetInteractive/gi , /Adnetik/gi , /Adreactor/gi , /Adrolays/gi , /Adroll/gi , /Advertise.com/gi , /Advertising.com/gi , /Adxpose/gi , /Adzerk/gi ,/affinity/gi , /AggregateKnowledge/gi , /AlexaMetrics/gi , /AlmondNet/gi , /Aperture/gi , /BTBuckets/gi , /Baynote/gi , /Bing/gi , /Bizo/gi , /BlogRollr/gi , /Blogads/gi , /BlueKai/gi , /BlueLithium/gi , /BrandReach/gi , /BrightTag/gi , /Brightcove/gi , /Brightroll/gi , /Brilig/gi , /BurstMedia/gi , /BuySellAds/gi , /CNETTracking/gi , /CPXInteractive/gi , /CasaleMedia/gi , /CedexisRadar/gi , /CertonaResonance/gi , /Chango/gi , /ChannelAdvisor/gi , /ChartBeat/gi , /Checkm8/gi , /Chitika/gi , /ChoiceStream/gi , /ClearSaleing/gi , /ClickDensity/gi , /Clickability/gi , /Clicksor/gi , /Clicktale/gi , /Clicky/gi , /CognitiveMatch/gi , /Collarity/gi , /CollectiveMedia/gi , /Comscore Beacon/gi , /Connextra/gi , /ContextWeb/gi , /CoreMetrics/gi , /CrazyEgg/gi , /Criteo/gi , /Cross PixelMedia/gi , /CrowdScience/gi , /DC Storm/gi , /Dapper/gi , /DedicatedMedia/gi , /Demandbase/gi , /Demdex/gi , /DeveloperMedia/gi , /Didit/gi , /DiggWidget/gi , /DiggThis/gi , /Disqus/gi , /Dotomi/gi , /DoubleVerify/gi , /Doubleclick/gi , /DynamicLogic/gi , /EffectiveMeasure/gi , /Eloqua/gi , /Ensighten/gi , /EpicMarketplace/gi , /Etology/gi , /Evidon/gi , /Exponential/gi , /EyeWonder/gi , /Facebook Beacon/gi , /FacebookConnect/gi , /FederatedMedia/gi , /Feedjit/gi , /FetchBack/gi , /Flashtalking/gi , /ForeseeResults/gi , /FoxAudienceNetwork/gi , /FreeWheel/gi , /GetSatisfaction/gi , /Gigya/gi , /GlamMedia/gi , /Gomez/gi ,  /GoogleAdsense/gi , /GoogleAdwordsConversion/gi , /GoogleAnalytics/gi , /GoogleFriendConnect/gi , /GoogleWebsiteOptimizer/gi , /GoogleWidgets/gi , /Gravatar/gi , /Gravity/gi , /Hellobar/gi , /HitTail/gi , /Hurra/gi , /InfoLinks/gi , /Inkfrog/gi , /InsightExpress/gi , /InterClick/gi , /InviteMedia/gi , /Iovation/gi , /KissMetrics/gi , /KonteraContentLink/gi , /KruxDigital/gi , /LeadLander/gi , /Leadformix/gi , /Leadsius/gi , /LifeStreet Media/gi , /Lijit/gi , /LinkedIn/gi , /Linkshare/gi , /LiveInternet/gi , /LivePerson/gi , /Lotame/gi , /LucidMedia/gi , /LyrisClicktracks/gi , /MAGNETIC/gi , /MSNAds/gi , /MarinSoftware/gi , /MarketGID/gi , /Marketo/gi , /MaxPointInteractive/gi , /Maxymizer/gi , /MediaInnovationGroup/gi , /Media6Degrees/gi , /MediaMath/gi , /MediaMind/gi , /MediaPlex/gi , /Meebo/gi , /Mercent/gi , /Meteor/gi , /MicrosoftAnalytics/gi , /MicrosoftAtlas/gi , /MindsetMedia/gi , /Mint/gi , /Mixpanel/gi , /Monetate/gi , /MyBlogLog/gi , /NDN/gi , /Navegg/gi , /NetMining/gi , /NetShelter/gi , /NetratingsSiteCensus/gi , /NewRelic/gi , /NewsRight/gi , /NextAction/gi , /Nuggad/gi , /Omniture/gi , /OpenAds/gi , /OpenX/gi , /Optimizely/gi , /Optimost/gi , /OutBrain/gi , /OwnerIQ/gi , /PO.ST/gi , /Parse.ly/gi , /Piwik/gi , /PointRoll/gi , /PostRank/gi , /Pubmatic/gi , /Qualaroo/gi , /Quantcast/gi , /QuigoAdsonar/gi , /RadiumOne/gi , /RapLeaf/gi , /RealMedia/gi , /Reinvigorate/gi , /Relestar/gi , /RevenueScience/gi , /RevenueMantra/gi , /RightMedia/gi , /RocketFuel/gi , /Rubicon/gi , /RubiconProject/gi , /SafeCount/gi , /Salesforce/gi , /ShareThis/gi , /SiteMeter/gi , /SiteScout/gi , /SkimLinks/gi , /Smart Adserver/gi , /Snaps/gi , /Snoobi/gi , /Specific Meida/gi , /SpecificClick/gi , /Sphere/gi , /StatCounter/gi , /TARGUSinfoAdAdvisor/gi , /Taboola/gi , /Tacoda/gi , /TeaLeaf/gi , /Tealium/gi , /Technorati/gi , /TechnoratiMedia/gi , /Tellapart/gi , /Teracent/gi , /TestandTarget/gi , /TidalTV/gi , /TorbitInsight/gi , /TradeDoubler/gi , /TravelAdvertising/gi , /TremorVideo/gi , /TribalFusion/gi , /Tumri/gi , /Turn/gi , /TweetMeme/gi , /TwitterBadge/gi , /TyntTracer/gi , /Typekit/gi , /UnderdogMedia/gi , /UndertoneNetworks/gi , /Unica/gi , /ValueClick/gi , /ValuedOpinions/gi , /VibrantAds/gi , /VigLink/gi , /VisualSciences/gi , /VisualWebsiteOptimizer/gi , /VisualRevenue/gi , /ViziSense/gi , /Vizu/gi , /Vizury/gi ,/WebAds/gi , /Webtrends/gi , /Whos.amung.us/gi , /Wibiya/gi , /Woopra/gi , /WordpressStats/gi , /WorldNow/gi , /XGraph/gi , /Yadro/gi , /YahooBuzz/gi , /YahooWebAnalytics/gi , /YuMeNetworks/gi , /Zango/gi , /Zedo/gi , /Zemanta/gi ,  /e-planning/gi , /eXTReMe Tracking/gi , /eXelate/gi , /etracker/gi , /iPerception/gi, /bs.serving-sys.com/gi, /hitwebcounter/gi, /freecounterstat/gi, /yieldmanager/gi, /adnxs/gi, /scorecard/gi);

/*plugin score */
var plugcnt = 0;

/*variables for sending log details to panel widget
 * (meta, iframe, unauth red,encoded js, ext domains respectively)
 */
var warns="",warns1="",warns2="",warns3="",Domainreport="";

/* patterns */
var patt=/www/gi, patt1=/http/gi;
var TLDS = new Array(/com/gi, /net/gi, /in/gi);

/*variables for scrptTag function*/
var scrpa="";

/*variables for imgTag function*/
var socpa="";

/*variables for iframeTag function*/
var alert2="", count=0;

/*variables for scriptTag function*/
var alert2sc="", countsc=0;

/*variables for encodeJS function*/
var alert3="",encode1="";

/*variables for UATag function*/
var alert2UA="", countUA=0;

/*other tags like object, meta, anchor and link*/
var plugs="",vulplug="",redirect1="",red1="",redirect2="",red2="";

/*Retreiving domain name from the URL*/
var hostt, host;
hostt = window.location.host;
host = hostt.replace('http://','').replace('https://','').replace('www.','').split(/[/?#]/)[0];

// It holds the tags to be monitored in the incoming web page
var monitorTags = new Array("script","img","area","link","frame","form","embed","applet","meta","object","iframe");

//variables to corresponding tags
var tagsArray = new Array("scrtag", "imgsrc", "are","lin","fra","frm","emb","app","met","obje","ifr");

//attributes of corresponding tags
var attrArray = new Array("src", "src","href","href","src","action","src","codebase","content","classid","src");

for(var i = 0; i<monitorTags.length; i++) 
{
    if((document.getElementsByTagName(monitorTags[i])).length > 0)
    {
        switch(i)
        {
            case 0:scrptTag();
                break;
            case 1:imgTag();
                break;
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
            case 8:
            case 9:findhref();
                break;
            case 10:iframeTag();
                break;

            default: warns +="no tags"+ "<br>";

        }

    }
}

/*individual functions of switch */

/* This function monitors the iframe tags in the incoming web page */
function iframeTag()
{
	var k,ifrm,widt,hgt,styl,src;
	ifrm = document.getElementsByTagName("iframe");

	/* Monitoring and checking width, height and style properties of every iframe*/ 
	for(k=0;k<ifrm.length;k++)
	{
		widt=ifrm[k].getAttribute("width");
		hgt=ifrm[k].getAttribute("height");
		styl=ifrm[k].getAttribute("style");
		src =ifrm[k].getAttribute("src");
		if(src===null || src === "/blank.html" || src === "about:blank"){
			continue;
		}
		/*if the height or width of iframe is very small, i.e, lessthan 3 */
		if(hgt < 3 && hgt !== null) {
			domainmatch(src,ifrm,k);					
		}
		if(widt < 3 && widt !== null){
			domainmatch(src,ifrm,k);		
		}

		/* if style property contains height, width or some content and if "src" present */
		if(styl){
			
			var str, d=0;
			if(styl.match(/;/)) {
				var arr_str = styl.split(";");
				while(d < arr_str.length){
					str = arr_str[d].split(":");
					if(str[0] === "height" || str[0] === "width"){ 
						var ext = str[1].substring(0, str[1].length-2);
						if(ext < 3){
							domainmatch(src,ifrm,k);
						}
					}
                    
                                        else if(str[0] === "left" || str[0] === "right" || str[0] === "top" || str[0] === "bottom"){ 
						var ext1 = str[1].substring(0, str[1].length-2);
						if(ext1 < -99){
							domainmatch(src,ifrm,k);
						}
					}
					else if(str[0] === "visibility" || str[0] === "display"){

						if(str[1].match(/hidden/gi) || str[1].match(/none/gi)){
							domainmatch(src,ifrm,k);
						}
					}
					d++;
				}
			}
			else if(styl.match(/:/))
			{
				str = styl.split(":");
				if(str[0] === "visibility" || str[0] === "display"){
					if(str[1].match(/hidden/gi) || str[1].match(/none/gi)){
						domainmatch(src,ifrm,k);
					}
				}
			}
		}
        
		/* write code to find domain in src if it iframe not hidden */
		if(src) 
		{
                    extdomain(src);
		}	
	}
}

/*
 * Cross verify the source of the hidden iframe property with the host name 
 * of the original URL and if it does not belongs to the same origin then 
 * alerts the user 
 * */

function domainmatch(src,ifrm,k)
{
	var flag=0,src1;
	src1=src.replace('http://','').replace('https://','').replace('www.','').split(/[/?#]/)[0];

	if(alert2.match(src1) === null){           
		for(var m=0;m<whitelist.length;m++)
		{
			if(src1.match(whitelist[m]) !== null){

				var n=whitelist[m].toString().length;
				var temp=whitelist[m].toString().substring(1,n-3);
				if(redirect1.match(temp) === null){
					redirect1+=whitelist[m].toString().substring(1,n-3)+"<br>";
				}
				flag=1;
				return;
			}
		}
		if(flag===0 && !alert2){
			alert2 += "\n"+src1; count++;
			warns1 += "<b>HTML:Hidden Iframe</b>"+"<br>"+"<b>URL(s)::</b><br>==>" +src+"<br>";          
			//ifrm[k].setAttribute("src",null);
		}
        	else if(flag===0 && alert2 && warns1.match(src1) === null){
			alert2 += "\n"+src1;count++;
			warns1 += "<br>==>"+src+"<br>";          
			//ifrm[k].setAttribute("src",null);
		
		}
	}
	
}

/*
 * Monitoring UnAuthorized redirections through image tag
 * @returns {undefined}
 */
function imgTag()
{
    var i, k, wid, hig, len, soc, soc1, flag = -1;
    /*
     * Image formats to be monitored
     * @type Array
     */
    var format = new Array(/png/gi, /jpg/gi, /gif/gi, /bmp/gi, /jpeg/gi, /Icons/gi, /ico/gi, /amp/gi);
    var imgsrc = document.getElementsByTagName("img");
      
    len = imgsrc.length;
    for(i=0;i<len;i=i+1)
    {
        var flag1=0;
        soc = imgsrc[i].getAttribute("src");
        wid = imgsrc[i].getAttribute("width");
        hig = imgsrc[i].getAttribute("height");

        if(soc === null ){
                continue;
        }

        socpa=getFileName(soc);			
        soc1=soc.replace('http://','').replace('https://','').replace('www.','').split(/[/?#]/)[0];
        var parts = soc1.split('.');
        var socc = parts.slice(-1).join('.');
	// whitelist TLDS for reduce false positive
        /*for(var m=0;m<TLDS.length;m++)
        {
                if(socc.match(TLDS[m]) !== null){
                        flag1=1;
                }
        }*/
	//if it is tracker, stop here
	for(var m=0;m<whitelist.length;m++)
		{
			if(soc1.match(whitelist[m]) !== null){

				var n=whitelist[m].toString().length;
				redirect1+=whitelist[m].toString().substring(1,n-3)+"<br>";
				flag=1;
				return;
			}
		}
	// if it is same origin or tracker stop here
        if(host.match(soc1) !== null || soc.match(host) !== null || flag1 === 1){
                continue;
        }	
        for(k=0; k<format.length; ++k)
        {
                //searching for image extensions, i.e. .jpg.........
                if(soc.match(format[k]) !== null) {
                        if(socpa) {
                                if(socpa.match(".php\\.")!==null ){
                                        domainmatchUA(soc1);

                                }
                        }

                        flag = 1;
                        break;
                }
        }if(flag !== 1) { 

                if(socpa){
                        if(socpa.match("\\.php")!==null ){
                                domainmatchUA(soc1);
                        }
                }

        }


        // If the image is hidden, hidden activity will be displayed in the panel
        if((wid < 1 && wid !== null)||(hig < 1 && hig !== null))
        {
               warns2 += "<br><b>Threat::Hidden Image::</b>"+"<br>==>"+soc+"<br>";
        }
        else {

                extdomain(soc);
        }
    }
}

/*
 * Monitoring Script tag for detecting UnAuthorized redirections and 
 * Encoded JavaScript
 * @returns {undefined}
 */
function scrptTag()
{
	var len, scr,scr1,scrr, patt2=/.js/g;
	var scrpt = document.getElementsByTagName("script");
	var totalScript = "";
        var enablewordsize=0,enableinddigiden=0;
	
    	len = scrpt.length;
	for(var i=0;i<len;i++)
	{
        	//encoded js detection        
                var scriptstring = scrpt[i].innerHTML;
		scriptstring = scriptstring.replace(/(\r\n|\n|\r)/gm,""); //convert the innerHTML to one line, easier to match
		//scriptstring=scriptstring.replace(/(\/\*([\s\S]*?)\*\/)|(\/\/(.*)$)/gm, ''); //to remove commented javascript // or /* */
		scriptstring = scriptstring.replace(/<!--[\s\S]+?-->/g,"");   //to remove commented javascript <!-- //-->
		scriptstring = scriptstring.replace(/<![CDATA[\s\S]+?]]>/g,""); // //to remove commented javascript <![CDATA //]]>               

                
                if(scriptstring.length>250){
			/*
                         * dividing the script string into lines, words and 
                         * then calculating word size
                        */

			var words;
			var lines = scriptstring.split(";");                
			for(var m = 0; (lines !== null) && (m<lines.length); m++) {
				words = lines[m].split(" ");                
				for(var k = 0; (words !== null) && (k<words.length); k++) {
					if(words[k].length > 6500){
                        			enablewordsize++;
					}
				}
			}
                        
                        // pecentage of digits in each script 
			var indScriptLength = scriptstring.length;
			var indNumLength = scriptstring.replace(/\D/g, '').length;
			var inddigitdensity=((indNumLength*100)/indScriptLength);
			if(((indNumLength*100)/indScriptLength) >= 30){
            			enableinddigiden++;
			}

                        /* n-gram for individual script*/
			var specialChars = new Array (/%/g,/$/g,/</g,/>/g,/@/g,/!/g,/#/g,/^/g,/&/g,/\*/g,/\(/g,/\)/g,/_/g,/\+/g,/\[/g,/\]/g,/\{/g,/\}/g,/\?/g,/:/g,/;/g,/'/g,/"/g,/,/g,/\./g,/\//g,/~/g,/\`/g,/-/g,/=/g,/\\/g, /u/g, /x/g);
			var totalnumbersc=0, encodenumbers=0, encodedanddigitnumbers=0;
			for(var n = 0; n < specialChars.length;n++){
				if(scriptstring.match(specialChars[n])){
					totalnumbersc +=scriptstring.match(specialChars[n]).length;
					if(n==0 || n==3 || n== 4 || n == 5 || n == 7 || n==8 || n==10 || n==12 || n==18 || n==19 || n ==22 || n==23 || n==28 || n ==31 || n==32)
					{
						encodenumbers +=scriptstring.match(specialChars[n]).length;
					}
				}
			}
			encodedanddigitnumbers=(indNumLength) + (encodenumbers);
			var indspdensity=(encodedanddigitnumbers*100)/scriptstring.length;
						
			var scriptstringN = scriptstring.replace(/[^a-zA-Z]/g,'');
			var scriptstringNN = scriptstring.replace(/\</g,"&lt;");   //for <
			var scriptstringNNN = scriptstringNN.replace(/\>/g,"&gt;");   //for >
                	scriptstring = scriptstring.replace(/ /g,"");				
                           
                        /*
                         * Searching for the functions unescape and fromCharCode in the script string
                         */
			if((scriptstringN.match(/unescape/g) || scriptstringN.match(/fromCharCode/g) || (scriptstringN.indexOf(/fro/g) < scriptstringN.indexOf(/mCharCode/g) )|| (scriptstringN.indexOf(/fromChar/g) < scriptstringN.indexOf(/Code/g) ) || (scriptstringN.indexOf(/fr/g) < scriptstringN.indexOf(/omCh/g) < scriptstringN.indexOf(/arCode/g) ) || (scriptstringN.indexOf(/fro/g) < scriptstringN.indexOf(/mc/g) < scriptstringN.indexOf(/harCode/g)) || (scriptstringN.indexOf(/fr/g) < scriptstringN.indexOf(/omCh/g) < scriptstringN.indexOf(/arCo/g)< scriptstringN.indexOf(/de/g)) || (scriptstringN.indexOf(/fr/g) < scriptstringN.indexOf(/omC/g) < scriptstringN.indexOf(/ha/g)< scriptstringN.indexOf(/rCode/g))) && !alert3 && indspdensity > 58){

                    		alert3 += "Threat:: Encoded JavaScript Malware";
                    		warns3 += "<b>Threat:: Encoded JavaScript Malware</b>"+"<br>"+"<b>Malicious content is::</b><br>" +scriptstringNNN+"<br>";
                	}/*
                         * Searching for suspicious string pattenrs inside unescape function
                         */
			else if((scriptstringN.match(/unescape/g) && scriptstringN.match(/newArray/g) && scriptstring.match(/%u9090/g)) && !alert3 && indspdensity > 25){

                    		alert3 += "Threat:: Encoded JavaScript Malware";
                    		warns3 += "<b>Threat:: Encoded JavaScript Malware</b>"+"<br>"+"<b>Malicious content is::</b><br>" +scriptstringNNN+"<br>";
                	}/*
                         * Searching for hex code starting with var.
                         * This will be displayed in panel report
                         */                        
			else if(scriptstringN.match(/var/g)&& !encode1 && !warns3 && indspdensity > 57){
				encode1 += "<b>Threat:: Encoded JavaScript Malware</b>"+"<br>"+"<b>Malicious content is::</b><br> " +scriptstringNNN+"<br>";
			}
                }
        
		totalScript += scriptstring+" ";
        
        
		var flag1=0;    
		scr = scrpt[i].getAttribute("src");
		if(scr === null ){
			continue;
		}
		
		scr1=scr.replace('http://','').replace('https://','').replace('www.','').split(/[/?#]/)[0];
		        
		var parts = scr1.split('.');
		var scrr = parts.slice(-1).join('.');
		
		if(scr.match(patt2) !== null || ( scr.match(patt) !== null || scr.match(patt1) !== null)){
        	extdomain(scr);
		}
		// whitelist TLDS for reduce false positive
		/*for(var m=0;m<TLDS.length;m++)
		{
			if(scrr.match(TLDS[m]) !== null){
				flag1=1;
			}
		}*/
		if(host.match(scr1)!== null || scr.match(host) !== null )
		{
			continue;		
		}
		
		scrpa=getFileName(scr);
		if(scr.match(patt2) !== null){
			if(scrpa){
				if(scrpa.match("\\.js.php")!==null || scrpa.match("\\.php.js")!==null ){
					domainmatchUA(scr1);			
                		}
			}
        	}
		//checking for non js(php/asp) pattern
        	else {           		
            		if(scrpa){
                                if(scrpa.match("\\.php")!==null ){
                                    domainmatchUA(scr1);

                                }
                        }
		}
                // find extdomains
		if(scr.match(patt2) !== null || ( scr.match(patt) !== null || scr.match(patt1) !== null)){
			
			extdomain(scr);	
		}
    
	} //for loop ends
    
}
// Matches the UnAuth src property with the host name of the original URL and if it is not from same origin then alerts the user
function domainmatchUA(src)
{	
	var dots=src.match(/\./g);
	if(src === null || !dots )
		return;
    	  
	if(alert2UA.match(src) === null){          		
		if(!alert2UA){		
			alert2UA += "\n"+src; countUA++;
			warns2 += "<b>HTML:Redirector::</b>"+"<br><b>URL(s)::</b><br>==>"+src+"<br>"; 		
		}
        	else if(alert2UA && warns2.match(src) === null){		
			alert2UA += "\n"+src;countUA++;
			//warns2 += "Threat:: HTML:Redirector"+"<br>"+src+"<br>";	
			warns2 += "<br>==>"+src+"<br>";		
		}
	}	
}	
/*function is_valid_url(url)
{
     return url.match(/^(ht|f)tps?:\/\/[a-z0-9-\.]+\.[a-z]{2,4}\/?([^\s<>\#%"\,\{\}\\|\\\^\[\]`]+)?$/);
}*/
                        
function findhref()
{
        var conten;
	var pattmeta1=/refresh/gi, pattmeta2=/index.php?spl=/g;
	tagsArray[i] =document.getElementsByTagName(monitorTags[i]);

	var alink=tagsArray[i];
			
	for(var k=0;k<alink.length;k++)
	{
		var hr=alink[k].getAttribute(attrArray[i]);
		if(hr){ //error checking
			// display meta content
			if(i=== 8)
			{
				// code to stop meta redirection == bad idea in some cases
				/*
				var i, refAttr;
				var metaTags = document.getElementsByTagName('meta');
				for i in metaTags {
				    if( (refAttr = metaTags[i].getAttribute("http-equiv")) && (refAttr == 'refresh') ) {
					        metaTags[i].parentNode.removeChild(metaTags[i]);
    					}
				}
                                // report +="meta contains: "+hr+"\n";
				*/
				var str;
				
				var refres=alink[k].getAttribute("http-equiv");
				
				//    if meta contains refersh attribute	
				if(refres && refres.match(pattmeta1)!==null){
					//comparing content with known malicious patterns of meta content
					conten=alink[k].getAttribute("content");
					if(conten){
						if(conten.match(pattmeta2)!==null){
							warns +="meta redirected to known malicious contents<br>";	
						}
						else{
							// only url part
							str = conten.split(";");
							if(str[1] !== undefined && str[1].match(/url/gi) !== null){
								var src=str[1].replace('url=','');
								extdomain(src);
								warns+="in meta tag after "+str[0]+" seconds,it will redirect to "+src+"<br>";
								redirect2+="meta tag redirection to: "+src+"<br>";
							}
						}
					}
				}	
				continue;						
			}
                        /*
                         * Searching for the plugins inside the webpage and 
                         * detecting vulnerable plugins through object ID
                         */
			if(i===9)
			{
				plugcnt++;		
			/*	for(var m=0;m<clsidlist.length;m++)
				{						
					if(hr.match(clsidlist[m])!==null){
						warns+="vulnerable plugin<br>";
						vulplug+="Threat:vulnerable plugin invoked<br><br>";
					}
				}
			*/
			}	
                        /*
                         * Collecting all the external domains from various tags
                        */
			if(hr.match(patt) !== null || hr.match(patt1) !== null) 
			{
                		extdomain(hr);
			}
		}// if hr
	}//for
}

/*
 * This function gathers all the cross domain URLs coming through various 
 * vulnerable tags and filtering duplicate URLs and Same domain URLs
 * @param {type} src : URL is the argument
 * @returns {undefined}
 */
function extdomain(src)
{
        try{
            var src1;
    		src1=src.replace('http://','').replace('https://','').replace('www.','').split(/[/?#]/)[0];
			var dots=src1.match(/\./g);
			if((host.match(src1) === null && src1.match(host) === null) && Domainreport.match(src1)===null && dots){
				alert2sc += "\n"+src1; countsc++;
				Domainreport +="==>"+src1+"<br>";
				//isTracker(src1);
				for(var m=0;m<whitelist.length;m++)
				{
					if(src1.match(whitelist[m]) !== null){

						var n=whitelist[m].toString().length;
						var temp=whitelist[m].toString().substring(1,n-3);
						if(redirect1.match(temp) === null){
							redirect1+=whitelist[m].toString().substring(1,n-3)+"<br>";
						}					
					}
				}

				
			}
        }
        catch(e){
            
        }
}

/*
 * Retreiving the resource name from the URL
 * @param {type} path : URL including Resource name
 * @returns {unresolved} : Returns Resource Name
 */
function getFileName(path)
{
	if(path.match(/^((http[s]?|ftp):\/)?\/?([^:\/\s]+)(:([^\/]*))?((\/[\w/-]+)*\/)([\w\-\.]+[^#?\s]+)(\?([^#]*))?(#(.*))?$/i))
	{
		return path.match(/^((http[s]?|ftp):\/)?\/?([^:\/\s]+)(:([^\/]*))?((\/[\w/-]+)*\/)([\w\-\.]+[^#?\s]+)(\?([^#]*))?(#(.*))?$/i)[8];
	}
}

/*
 * Filling the default values for Reporting in Panel
 */
if(plugcnt){
	plugs +=plugcnt+" plugins loaded in this webpage<br>";
	if(vulplug){
            plugs +=vulplug+"<br>";
        }
}

/*
 * Displaying trackers and Static Redirections in Report
 */
if(redirect1){
	red1="Tracker(s) found:<br>"+redirect1;
}
if(redirect2){
	red2="Static html redirections:<br>"+redirect2;
}


// code for adding dynamic iframes + static iframes
var ifrd1= "",ifrd2="";
ifrd1=sessionStorage.getItem("alertif1");
//ifrd1=JSON.parse(ifrd1);
ifrd2=sessionStorage.getItem("alertif2");
//ifrd2=JSON.parse(ifrd2);

if(ifrd1){
	alertts=ifrd1;
}
if(ifrd2){
	alertts=ifrd2;
}
if(ifrd1 && ifrd2){
	alertts=ifrd1 + ifrd2;
}

//console.log("rcvd dynifr through session storage:",alertts); 
var lines = alertts.split("\n");  
var newlines=(lines.length)-1;
var count_if=0, alert_if;
if(alertts != alert2){
	count_if = newlines + count;
	alert_if = alertts + alert2;
}
else{
	count_if = count;
	alert_if = alert2;
}

var scd1= "",scdd1="",scd2="",scdd2="",ress="";
scd1=sessionStorage.getItem("alertsc1");
scdd1=JSON.parse(scd1);
scd2=sessionStorage.getItem("alertsc2");
scdd2=JSON.parse(scd2);
if(scdd1){
	ress=scdd1;
}
if(scdd2){
	ress=scdd2;
}
if(scdd1 && scdd2){
	ress=scdd1+scdd2;
}


// code for adding dynamic scripts + static scripts
var lines1 = ress.split("\n");  
var newlines1=(lines1.length)-1;
var count_sc=0, alert_sc=""; 
if(alert2UA != ress){
	count_sc=newlines1+countUA;
	alert_sc=ress+alert2UA;
}
else{
	count_sc = countUA; 
	alert_sc = alert2UA;
}

var s2="", s1="";
var HostProto=proto+"//"+host; 


//framework.extension.fireEvent('HI', { data: {someData:HostProto, highlitedText:'CNN'}}); //hostname

var urlPort = browser.runtime.connect({name:"urlport-from-cs"});
var popupPort = browser.runtime.connect({name:"popupport-from-cs"});

urlPort.postMessage({"url": HostProto,"fullurl":fullurl});

//bl status rcvd
var flag=0, blstatus="", Head="CDAC's Browser JSGuard Warning";

var blstatus_if="";
var blstatus_sc="";


//again common
var gsbreq=count_if+alert_if;
if(count_if){

	s2='Threat:: Hidden Iframe<br>Evil URL(s) are :::'+alert_if+"<br>";

	
}

var gsbreq1=count_sc+alert_sc;
if(count_sc){


	s1='Threat:: UnAuthorized Redirection<br>Evil URL(s) are :::'+alert_sc+"<br>";



}

var frameEl =  window.frameElement;

var ps = localStorage.getItem(0);
console.log("");
if(ps == null || ps.match(HostProto) == null){     //iniatiall null and host diffrenet so block
	if(alert_if || alert3 || alert_sc)
	{       
		if(alert_if && frameEl === null){



	//gsbreq="1\nhttp://malware.testing.google.test/testing/malware/";

	var xhr = new XMLHttpRequest();
	xhr.open('POST', 'https://sb-ssl.google.com/safebrowsing/api/lookup?client=firefox&apikey=ABQIAAAAxhNVFd2Bkr2PLooc8AycwBRHPfqIBBZIjrF8eFFZCSSGcCk3eg&appver=1.5.2&pver=3.0', true);

	//Send the proper header information along with the request
	xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");

	xhr.onreadystatechange = function() {//Call a function when the state changes.
    	

	if (xhr.readyState === 4) {

	    if (xhr.status === 200) {

		//console.log("IN CONTENT SCRIPT: response from GSB:"+xhr.responseText);
		
		blstatus_if=xhr.responseText;
	//console.log("if blstatus rcvd"+blstatus_if);
				if(blstatus_if.match("malware") || blstatus_if.match("phising") || blstatus_if.match("phishing,malware")){
					flag=1;
					//console.log("and here is an iframealert");
					document.body.innerHTML = "";//$('head link').remove();
					var r=jConfirm("<b>In the requested webpage at URL</b><br><br>"+hostt+"<br><br><b>Threat has been found:</b><br><br>"+s2+"<br>To get more information click on widget shown in toolbar<br><br>", Head ,function(r) {
							if(r== false){	
                        
								//console.log("false");			            	        		
								var d1 = new Date ();											
								var oneday = new Date(d1);
								//console.log("1: "+oneday);
								//oneday.setHours(d1.getHours(),d1.getMinutes() + 2); //one day from now
								oneday.setDate(d1.getDate() + 1); //one day from now
								//console.log("2: "+oneday);	

								localStorage.setItem(0, HostProto);

								localStorage.setItem(1, oneday);
								location.reload();
							}
						});
				}

	    } else {
		      console.log('error: '+xhr.statusText);
	    }
	  }
	};
	xhr.send(gsbreq); 


			
			/*	console.log("if blstatus rcvd"+blstatus_if);
				if(blstatus_if.match("malware") || blstatus_if.match("phising") || blstatus_if.match("phishing,malware")){
					flag=1;
					console.log("and here is an iframealert");
					document.body.innerHTML = "";//$('head link').remove();
					var r=jConfirm("<b>In the requested webpage at URL</b><br><br>"+hostt+"<br><br><b>Threat has been found:</b><br><br>"+s2+"<br>To get more information click on widget shown in toolbar<br><br>", Head ,function(r) {
							if(r== false){	
                        
								//console.log("false");			            	        		
								var d1 = new Date ();											
								var oneday = new Date(d1);
								//console.log("1: "+oneday);
								//oneday.setHours(d1.getHours(),d1.getMinutes() + 2); //one day from now
								oneday.setDate(d1.getDate() + 1); //one day from now
								//console.log("2: "+oneday);	

								localStorage.setItem(0, HostProto);

								localStorage.setItem(1, oneday);
								location.reload();
							}
						});
				}*/
		}
		if (alert3 && flag == 0){

			flag = 1;
	    		document.body.innerHTML = "";//$('head link').remove();flag=1;
	    	
			var r=jConfirm("<b>In the requested webpage at URL</b><br><br>"+hostt+"<br><br><b>Threat has been found:</b><br><br>"+alert3+"<br><br>To get more information click on widget shown in toolbar<br><br>", Head ,function(r) {
							if(r== false){	
                        
								//console.log("false");			            	        		
								var d1 = new Date ();											
								var oneday = new Date(d1);
								//console.log("1: "+oneday);
								//oneday.setHours(d1.getHours(),d1.getMinutes() + 2); //one day from now
								oneday.setDate(d1.getDate() + 1); //one day from now
								//console.log("2: "+oneday);	

								localStorage.setItem(0, HostProto);

								localStorage.setItem(1, oneday);
								location.reload();
							}
						});
		}
		if(alert_sc && flag == 0){



			//gsbreq1="1\nhttp://malware.testing.google.test/testing/malware/";

			var xhr = new XMLHttpRequest();

			xhr.open('POST', 'https://sb-ssl.google.com/safebrowsing/api/lookup?client=firefox&apikey=ABQIAAAAxhNVFd2Bkr2PLooc8AycwBRHPfqIBBZIjrF8eFFZCSSGcCk3eg&appver=1.5.2&pver=3.0', true);

			//Send the proper header information along with the request
			xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");

			xhr.onreadystatechange = function() {//Call a function when the state changes.
    	

			if (xhr.readyState === 4) {

	    			if (xhr.status === 200) {

					//console.log("IN CONTENT SCRIPT: response from GSB:"+xhr.responseText);
		
					blstatus_sc=xhr.responseText;
					//console.log("if blstatus rcvd"+blstatus_sc);
					if(blstatus_sc.match("malware") || blstatus_sc.match("phising") || blstatus_sc.match("phishing,malware")){
						flag=1;
						//console.log("and here is an scriptalert");
						document.body.innerHTML = "";//$('head link').remove();
						var r=jConfirm("<b>In the requested webpage at URL</b><br><br>"+hostt+"<br><br><b>Threat has been found:</b><br><br>"+s2+"<br>To get more information click on widget shown in toolbar<br><br>", Head ,function(r) {
							if(r== false){	
                        
								//console.log("false");			            	        		
								var d1 = new Date ();											
								var oneday = new Date(d1);
								//console.log("1: "+oneday);
								//oneday.setHours(d1.getHours(),d1.getMinutes() + 2); //one day from now
								oneday.setDate(d1.getDate() + 1); //one day from now
								//console.log("2: "+oneday);	

								localStorage.setItem(0, HostProto);

								localStorage.setItem(1, oneday);
								location.reload();
							}
						});
					}

	    			} else {
		      			//console.log('genuine: '+xhr.statusText);
	    			}
	  		}
		};
		xhr.send(gsbreq1); 



				/*console.log("if blstatus rcvd"+blstatus_sc);
				if(blstatus_sc.match("malware") || blstatus_sc.match("phising") || blstatus_sc.match("phishing,malware")){
					flag=1;
					console.log("and here is an script alert");
					document.body.innerHTML = "";//$('head link').remove();
					var r=jConfirm("<b>In the requested webpage at URL</b><br><br>"+hostt+"<br><br><b>Threat has been found:</b><br><br>"+s1+"<br>To get more information click on widget shown in toolbar<br><br>", Head ,function(r) {
							if(r== false){	
                        
								//console.log("false");			            	        		
								var d1 = new Date ();											
								var oneday = new Date(d1);
								//console.log("1: "+oneday);
								//oneday.setHours(d1.getHours(),d1.getMinutes() + 2); //one day from now
								oneday.setDate(d1.getDate() + 1); //one day from now
								//console.log("2: "+oneday);	

								localStorage.setItem(0, HostProto);

								localStorage.setItem(1, oneday);
								location.reload();
							}
						});
				}*/
		}
   

	}   

}
else{

var values = localStorage.getItem(1);
values = new Date(values);
var d = new Date();
var m=values-d;              //not working "values" and "n" vars  are damaged
//console.log("future: "+values+" len: "+values.length);
//console.log("current: "+d+" len: "+d.length);
//console.log("diff: "+m);
if (m<0) {
    localStorage.removeItem(0);localStorage.removeItem(1);localStorage.removeItem(2);
}
}
	var x=[];
	x.push(HostProto);		//hostonly
  	x.push(s2);        	// hidden iframe
  	x.push(s1);  	// unauth red
  	x.push(warns3);	//encode status
  	x.push(red2);		//meta
  	x.push(Domainreport);	//ext domain
  	x.push(red1);		//trackers


popupPort.postMessage({"popupinfo": JSON.stringify(x)});

});


