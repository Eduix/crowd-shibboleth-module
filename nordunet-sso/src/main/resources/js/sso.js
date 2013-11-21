var SSO = {
    initialized: false,
    loaded: false,
    config: {
        emailSet: true,
        urls: []        
    },
    loadedUrls: [],
    failedUrls: [],
    load: function() {
        if(!this.initialized) {
            for(var i=0; i<this.config.urls.length;i++) {
                var url = this.config.urls[i];
                $("#sso-container").append('<img src="'+url+'" width="1" height="1"/>');
            }
            _this = this;
            $('#sso-container img').imagesLoaded({
                done: function(images) {
                    $.each(images, function(idx,val) {
                        _this.imageLoaded(val);
                    });                    
                },
                fail: function(images, proper, broken) {                    
                    $.each(proper, function(idx,val) {
                        _this.imageLoaded(val);
                    });
                    $.each(broken, function(idx,val) {
                        _this.imageFailed(val);
                    });
                },
                always: function() {
                    _this.reportStatus();
                }
            });
            this.initialized = true;
        }
    },
    reportStatus: function() {
        if(!this.loaded) {
            this.loaded = true;
            var canContinueToOriginalDestination = true;
            if(this.loadedUrls.length==this.config.urls.length) {
                $("#logging-message").text("Logged in to all domains");
            } else {
                var failedDomains = "";
                _this = this;
                $.each(this.failedUrls, function(index, value) {
                    var domainParts = value.split("/")[2].split(".");
                    var domain = "."+domainParts.slice(1,domainParts.length).join(".");
                    failedDomains += "<li>" + domain + "</li>";
                    if(typeof _this.config.goTo != "undefined" && _this.config.goTo.indexOf(domain) != -1) {
                        canContinueToOriginalDestination = false;
                    }
                });
                var failText = "Could not log in to all domains. Single sign on failed for the following domains:";
                if(this.failedUrls.length==1) {
                    failText = "Could not log in to all domains. Single sign on failed for the following domain:";
                }
                $("#logging-message").text(failText).addClass("error").after("<ul id='failed-domains'>"+failedDomains+"</ul>");
            }
            // All domains loaded - insert required links to page
            var redirectDelay = 0;
            if(!this.config.emailSet) {
                $("#content").append('<p>You do not have an email address set. You can set one <a href="/crowd/plugins/servlet/setEmail">here</a></p>');
                redirectDelay = 10000;
            }
            if(typeof this.config.goTo != "undefined") {
                if(canContinueToOriginalDestination) {
                    if(this.failedUrls.length>0) {
                        $("#content").append('<p>You can still continue to your <a href="'+this.config.goTo+'">original destination</a></p>');
                    } else {
                       var goTo = this.config.goTo;
                       if(redirectDelay>0) {
                        $("#content").append('<p>You will be redirected to your <a href="'+this.config.goTo+'">original destination</a> in '+(redirectDelay/1000)+' seconds.</p>');
                        setTimeout(function(){
                            window.location.href=goTo;
                            },redirectDelay);
                       } else {                          
                          window.location.href=goTo;
                       }
                    }
                } else {
                    $("#content").append('<p>Login failed for your <a href="'+this.config.goTo+'">original destination</a></p>').addClass("error");
                }
            }
        }
    },
    imageLoaded: function(image) {
        if($(image).attr("src")) {
            this.loadedUrls.push($(image).attr("src"));            
        }
    },
    imageFailed: function(image) {
        if($(image).attr("src")) {
            this.failedUrls.push($(image).attr("src"))
        }
    }
}
