

class BadInputError extends Error {
    constructor(message: any){
        super(message)
        this.name = "BadInputError"
        this.message = (message || "")
    }
}

export {
    BadInputError
}