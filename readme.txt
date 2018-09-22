use testCodebattle
db.createUser({user:"codebattle",pwd:"test",roles: ["readWrite"], passwordDigestor: "server" })