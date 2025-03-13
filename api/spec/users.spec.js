const axios = require("axios")
 inst_axios = axios.create({
    baseURL: 'http://localhost:4000/'
})
/*describe("A suite is just a function", function() {
    let a;
  
    it("and so is a spec", function() {
      a = false;
      
      expect(a).toBe(true);
    });
  });*/


      
describe("The route", function(){
    let user_id = ""
    const data_user = {firstname: "first" , lastname: "last" , username: "user" , email: "email@email.com" , password: "password" , role: "admin"};
    const data_login = {email: "email@email.com" , password: "password"}
    const data_article = {article: "article"};
    const data_crypto = {crypto: "crypto"};
    const data_update = {firstname: "first1"}
    const style = "\n***********" + "    "
    const color = '\x1b[32m%s\x1b[0m'


    beforeAll( async () => {
        console.log("=========================================================== Users Test ======================================================================")

            let res = await inst_axios.post("/register" , data_user)
    
      
            res = await inst_axios.post("/login" , data_user)
            let t = "Bearer " +  res.data.data.token
            //console.log(t)
            inst_axios.defaults.headers.common['authorization'] = t
           
    })

    afterAll (async () => {
        let res = await inst_axios.get("/users/user?username=user")
        user_id = res.data.data.id
        res = await inst_axios.delete("/users/user/" + user_id)
    })


    it ("GET /users/user?username must return status 200" , async () => {
        const res = await inst_axios.get("/users/user?username=user")
        user_id = res.data.data.id
        //console.log(res.data)
        expect(res.data.message).toBe("User found")
        console.log(color , style + res.data.message + "\n")
    })

    it ("GET /users must return status 200" , async () => {
        const res = await inst_axios.get("/users")
        //console.log(res.data)
        expect(res.data.message).toBe("users")
        console.log(color , style + res.data.message  + "\n")
    })

    it ("PUT /users/user/:id must return status 200" , async () => {
        let res = await inst_axios.get("/users/user?username=user")
        user_id = res.data.data.id
        res = await inst_axios.put("/users/user/" + user_id , data_update)
        //console.log(res.data)
        expect(res.data.message).toBe("Successfully update the user")
        console.log(color , style + res.data.message + "\n")
    })

    it ("POST /users/update_article must return status 200" , async () => {
        let res = await inst_axios.get("/users/user?username=user")
        user_id = res.data.data.id
        res = await inst_axios.post("/users/update_article/" + user_id , data_article)
        expect(res.data.message).toBe("Successfully update the article")
        console.log(color , style + res.data.message + "\n")
    })

    it ("POST /users/update_crypto must return status 200" , async () => {
        let res = await inst_axios.get("/users/user?username=user")
        user_id = res.data.data.id
        res = await inst_axios.post("/users/update_crypto/" + user_id , data_crypto)
        expect(res.data.message).toBe("Successfully update the crypto")
        console.log(color , style +  res.data.message + "\n")
    })

})