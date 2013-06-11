var should = require("should"),
    FlokkStrategy = require("passport-flokk/strategy");

describe("FlokkStrategy", function() {

  var strategy;

  beforeEach(function() {
    strategy = new FlokkStrategy({
      clientID: "ABC123",
      clientSecret: "secret"
    }, function() {});
  });

  describe("strategy", function() {

    it("should be named flokk", function() {
      should.exist(strategy.name);
      strategy.name.should.eql("flokk");
    });

  });

  describe("userProfile", function() {


    describe("load profile", function() {

      var profile;

      beforeEach(function(done) {
        strategy._oauth2.get = function(url, accessToken, callback) {
          var body = '{"href": "https://api.theflokk.com/users/1", "username": "CamShaft", "id": "1", "name": "Cameron Bytheway", "email": [{"href":"cameron@nujii.com"}, {"href": "cameron@theflokk.com"}]}';

          callback(null, body, undefined);
        };

        strategy.userProfile("access-token", function(err, _profile) {
          if (err) return done(err);
          profile = _profile;
          done();
        });
      });

      it("should load the profile", function() {
        should.exist(profile);
        profile.should.be.an.object;
        profile.provider.should.eql('flokk');
        profile.id.should.eql('1');
        profile.username.should.eql('CamShaft');
        profile.displayName.should.eql('Cameron Bytheway');
        profile.profileUrl.should.eql('https://api.theflokk.com/users/1');
        profile.emails.length.should.eql(2);
        profile.emails[0].value.should.eql("cameron@nujii.com");
        profile.emails[1].value.should.eql("cameron@theflokk.com");
      });

    });

    describe("load error", function() {

      beforeEach(function() {
        strategy._oauth2.get = function(url, accessToken, callback) {
          callback(new Error('something-went-wrong'));
        }
      });

      it("should return an error", function(done) {
        strategy.userProfile("access-token", function(err, profile) {
          should.exist(err);
          should.not.exist(profile);
          done();
        });
      });

    });

  });

});