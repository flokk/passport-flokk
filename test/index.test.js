var should = require("should"),
    flokk = require("passport-flokk");

describe("passport-flokk", function() {
  describe("module", function() {

    it("should report a version", function() {
      should.exist(flokk.version);
      flokk.version.should.be.a.string;
    });

  });
});