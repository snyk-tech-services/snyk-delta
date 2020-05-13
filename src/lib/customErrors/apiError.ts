

class ApiError extends Error {
    constructor(message: any){
        super(message)
        this.name = "ApiError"
        this.message = (message || "")
    }
}

class ApiAuthenticationError extends Error {
    constructor(message: any){
        super(message)
        this.name = "ApiAuthenticationError"
        this.message = (message || "")
    }
}

class NotFoundError extends Error {
    constructor(message: any){
        super(message)
        this.name = "NotFoundError"
        this.message = (message || "")
    }
}

class GenericError extends Error {
    constructor(message: any){
        super(message)
        this.name = "Unknown"
        this.message = (message || "")
    }
}

export {
    ApiError,
    ApiAuthenticationError,
    NotFoundError,
    GenericError
}