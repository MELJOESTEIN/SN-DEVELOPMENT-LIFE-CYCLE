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
    const data_article = {article: {title: "article"}};
    const data_crypto = {crypto: {id: "crypto"}};
    const data_update = {firstname: "first1"}
    const style = "\n***********" + "    "
    const color = '\x1b[32m%s\x1b[0m'

    const anonym_create = { name: "default" ,nbrArticles: 3 , nbrCryptos: 3}
    const anonym_update = {name: "default"}

    beforeAll( async () => {
        console.log("=========================================================== Anonyms Test ======================================================================")
            let res = await inst_axios.post("/register" , data_user)
    
      
            res = await inst_axios.post("/login" , data_user)
            let t = "Bearer " +  res.data.data.token
            //console.log(t)
            inst_axios.defaults.headers.common['authorization'] = t
           
    })

    afterAll (async () => {
        let res = await inst_axios.get("/anonyms/anonym?name=default")
        user_id = res.data.data.id
        res = await inst_axios.delete("/anonyms/anonym/" + user_id)

        res = await inst_axios.get("/users/user?username=user")
        user_id = res.data.data.id
        res = await inst_axios.delete("/users/user/" + user_id)
    })


    it ("POST /anonyms/anonym must return status 200" , async () => {
        const res = await inst_axios.post("/anonyms/anonym" , anonym_create)
        expect(res.data.message).toBe("Successfully create this anonym")
        console.log( color, style +  res.data.message + "\n")
    })

    it ("GET /anonyms/anonym?name must return status 200" , async () => {
        const res = await inst_axios.get("/anonyms/anonym?name=default")
        //console.log(res.data)
        expect(res.data.message).toBe("Anonym found")
        console.log(color , style + res.data.message  + "\n")
    })
    
    it ("GET /anonyms/ must return status 200" , async () => {
        const res = await inst_axios.get("/anonyms/")
        //console.log(res.data)
        expect(res.data.message).toBe("anonyms")
        console.log(color  , style + res.data.message  + "\n")
    })

    /*it ("PUT /anonyms/anonym/:id must return status 200" , async () => {
        let res = await inst_axios.get("/anonyms/anonym?name=default")
        anonym_id = res.data.data.id
        res = await inst_axios.get("/anonyms/anonym/" + anonym_id , )
        
        res = await inst_axios.put("/users/user/" + user_id , data_update)
        //console.log(res.data)
        expect(res.data.message).toBe("Successfully update the user")
        console.log('\x1b[32m%s\x1b[0m' , "\n***********" +  "    " + res.data.message  + "    " + "\n")
    })*/

    it ("POST /anonyms/update_article/:id must return status 200" , async () => {
        let res = await inst_axios.post("/anonyms/update_article/" , data_article)
        expect(res.data.message).toBe("Successfully update the article")
        console.log(color , style + res.data.message + "\n")
    })

    it ("POST /anonyms/update_crypto must return status 200" , async () => {
        let res = await inst_axios.post("/anonyms/update_crypto/" , data_crypto)
        expect(res.data.message).toBe("Successfully update the crypto")
        console.log(color , style +  res.data.message  + "\n")
    })

})

