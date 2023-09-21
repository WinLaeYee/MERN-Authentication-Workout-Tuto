const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const validator = require('validator');

const Schema = mongoose.Schema

const userSchema = new Schema({
    email: {
        type: String,
        required:true,
        unique:true
    },
    password: {
        type: String,
        required: true
    }
})

// static signup method
userSchema.statics.signup= async function (email, password) { 
    // this keyword use htar lon arrow fun ma use bu async mar , this loh use tar ka model ka export loke htar tar pal moh loh, pee tot import function tot loke tal, so User model nay yar mar this ko use 

    //validation
    if(!email || !password){
        throw Error('All fields must be filled');
    }

    if(!validator.isEmail(email)){ //check valid email
        throw Error('Email is not valid')
    }

    if(!validator.isStrongPassword(password)){ // check strong password (a-z A-Z number special ch)
        throw Error('Password not strong enough')
    }

    const exists = await this.findOne({email})

    if(exists){
        throw Error('Email already in use')
    }

    const salt = await bcrypt.genSalt(10)
    const hash = await bcrypt.hash(password, salt);

    const user = await this.create({email, password: hash})
    
    return user;
}

// static login method
userSchema.statics.login = async function(email, password){
    if(!email || !password){
        throw Error('All fields must be filled');
    }

    const user = await this.findOne({email})

    if(!user){
        throw Error('Incorrect Email')
    }

    const match = await bcrypt.compare(password, user.password); // front: plain password, back: user hash password

    if(!match){
        throw Error('Incorrect Password')
    }

    return user;

}

module.exports = mongoose.model("User", userSchema)