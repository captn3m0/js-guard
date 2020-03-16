// jQuery Alert Dialogs Plugin

(function($) {
    $.alerts = {
        // These properties can be read/written by accessing $.alerts.propertyName from your scripts at any time
        verticalOffset: -75,                // vertical offset of the dialog from center screen, in pixels
        horizontalOffset: 0,                // horizontal offset of the dialog from center screen, in pixels/
        repositionOnResize: true,           // re-centers the dialog on window resize
        overlayOpacity: .01,                // transparency level of overlay
        overlayColor: '#FFF',               // base color of overlay
        draggable: true,                    // make the dialogs draggable (requires UI Draggables plugin)
        okButton: 'BLOCK THIS SITE&nbsp;',         // text for the OK button
        cancelButton: 'CONTINUE BROWSING&nbsp;', // text for the Cancel button
        dialogClass: null,                  // if specified, this class will be applied to all dialogs

        // Public methods
        alert: function(message, title, callback) {
            if( title == null ) title = 'Alert';
            $.alerts._show(title, message, null, 'alert', function(result) {
                if( callback ) callback(result);
            });
        },
        confirm: function(message, title, callback) {
            if( title == null ) title = 'Confirm';
            $.alerts._show(title, message, null, 'confirm', function(result) {
                    if( callback ) callback(result);
            });
        },

        prompt: function(message, value, title, callback) {
            if( title == null ) title = 'Prompt';
            $.alerts._show(title, message, value, 'prompt', function(result) {
                    if( callback ) callback(result);
            });
        },

        // Private methods

        _show: function(title, msg, value, type, callback) {

            $.alerts._hide();
            $.alerts._overlay('show');

            $("BODY").append(
                '<!--INFOLINKS_OFF-->' +
                '<div id="cdac_container">' +
                '<div id="cdac_title"></div>' +
                '<div id="cdac_content">' +
                '<div id="cdac_message"></div>' +
                '</div>' +
                '</div>');

            if( $.alerts.dialogClass ) $("#cdac_container").addClass($.alerts.dialogClass);

            // IE6 Fix
           // var pos = ($.browser.msie && parseInt($.browser.version) <= 6 ) ? 'absolute' : 'fixed'; 
             var pos = 'fixed';

            $("#cdac_container").css({
                position: pos,
                zIndex: 99999,
                padding: 0,
                margin: 0
            });

            $("#cdac_title").text(title);
            let san1 = DOMPurify.sanitize($("#cdac_title").text())
            $("#cdac_title").html($.parseHTML(san1));



            $("#cdac_content").addClass(type);
            $("#cdac_message").text(msg);
            let san2 = DOMPurify.sanitize($("#cdac_message").text().replace(/\n/g, '<br />'))
            $("#cdac_message").html($.parseHTML(san2));

            $("#cdac_container").css({
                minWidth: $("#cdac_container").outerWidth(),
                maxWidth: $("#cdac_container").outerWidth()
            });

            $.alerts._reposition();
            $.alerts._maintainPosition(true);

            switch( type ) {
                case 'alert':
                    $("#cdac_message").after('<div id="cdac_panel"><input type="button" value="' + $.alerts.okButton + '" id="cdac_ok" /></div>');
                    $("#cdac_ok").click( function() {
                            $.alerts._hide();
                            callback(true);
                    });
                    $("#cdac_ok").focus().keypress( function(e) {
                            if( e.keyCode == 13 || e.keyCode == 27 ) $("#cdac_ok").trigger('click');
                    });
                    break;
                case 'confirm':
                    $("#cdac_message").after('<div id="cdac_panel"><input class="cdac_inputgreen" type="button" value="' + $.alerts.okButton + '" id="cdac_ok" /> <input class="cdac_inputred" type="button" value="' + $.alerts.cancelButton + '" id="cdac_cancel" /></div>');
                    $("#cdac_ok").click( function() {
			    document.location.replace('about:Blank');
                            $.alerts._hide();
                            if( callback ) callback(true);
                    });
                    $("#cdac_cancel").click( function() {
                    //document.body.innerHTML = ";";
                    

                            $.alerts._hide();
                            if( callback ) callback(false);
                    });
                    $("#cdac_ok").focus();
                    $("#cdac_ok, #cdac_cancel").keypress( function(e) {
                            if( e.keyCode == 13 ) $("#cdac_ok").trigger('click');
                            if( e.keyCode == 27 ) $("#cdac_cancel").trigger('click');
                    });
                    break;
                case 'prompt':
                    $("#cdac_message").append('<br /><input type="text" size="30" id="cdac_prompt" />').after('<div id="cdac_panel"><input type="button" value="' + $.alerts.okButton + '" id="cdac_ok" /> <input type="button" value="' + $.alerts.cancelButton + '" id="cdac_cancel" /></div>');
                    $("#cdac_prompt").width( $("#cdac_message").width() );
                    $("#cdac_ok").click( function() {
                            var val = $("#cdac_prompt").val();
                            $.alerts._hide();
                            if( callback ) callback( val );
                    });
                    $("#cdac_cancel").click( function() {
                            $.alerts._hide();
                            if( callback ) callback( null );
                    });
                    $("#cdac_prompt, #cdac_ok, #cdac_cancel").keypress( function(e) {
                            if( e.keyCode == 13 ) $("#cdac_ok").trigger('click');
                            if( e.keyCode == 27 ) $("#cdac_cancel").trigger('click');
                    });
                    if( value ) $("#cdac_prompt").val(value);
                    $("#cdac_prompt").focus().select();
                    break;
            }

            // Making the Alert Box draggable
            if( $.alerts.draggable ) {
                try {
                        $("#cdac_container").draggable({ handle: $("#cdac_title") });
                        $("#cdac_title").css({ cursor: 'move' });
                } catch(e) { /* requires jQuery UI draggables */ }
            }
        },

        _hide: function() {
            $("#cdac_container").remove();
            $.alerts._overlay('hide');
            $.alerts._maintainPosition(false);
        },

        _overlay: function(status) {
            switch( status ) {
                case 'show':
                    $.alerts._overlay('hide');
                    $("BODY").append('<div id="cdac_overlay"></div>');
                    $("#cdac_overlay").css({
                        position: 'absolute',
                        zIndex: 99998,
                        top: '0px',
                        left: '0px',
                        width: '100%',
                        height: $(document).height(),
                        background: $.alerts.overlayColor,
                        opacity: $.alerts.overlayOpacity
                    });
                break;
                case 'hide':
                        $("#cdac_overlay").remove();
                break;
            }
        },

        _reposition: function() {
            var top = (($(window).height() / 2) - ($("#cdac_container").outerHeight() / 2)) + $.alerts.verticalOffset;
            var left = (($(window).width() / 2) - ($("#cdac_container").outerWidth() / 2)) + $.alerts.horizontalOffset;
            if( top < 0 ) top = 0;
            if( left < 0 ) left = 0;

            // IE6 fix
          //  if( $.browser.msie && parseInt($.browser.version) <= 6 ) top = top + $(window).scrollTop();

            $("#cdac_container").css({
                    top: top + 'px',
                    left: left + 'px'
            });
            $("#cdac_overlay").height( $(document).height() );
        },

        _maintainPosition: function(status) {
            if( $.alerts.repositionOnResize ) {
                    switch(status) {
                            case true:
                                    $(window).bind('resize', $.alerts._reposition);
                            break;
                            case false:
                                    $(window).unbind('resize', $.alerts._reposition);
                            break;
                    }
            }
        }

    }

    // Shortuct functions
    jAlert = function(message, title, callback) {
            $.alerts.alert(message, title, callback);
    }

    jConfirm = function(message, title, callback) {
            $.alerts.confirm(message, title, callback);
    };

    jPrompt = function(message, value, title, callback) {
            $.alerts.prompt(message, value, title, callback);
};
	
})(jQuery);
