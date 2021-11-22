

class BadInputError extends Error {
    constructor(message: any){
        super(message)
        this.name = "BadInputError"
        this.message = (message || "")
    }
}

class BadSnykTestOutput extends Error {
    constructor(message: any){
        super(message)
        this.name = "BadSnykTestOutput"
        this.message = (message || "")
    }
}

class PrintDepsError extends Error {
    constructor(message: any){
        super(message)
        this.name = "PrintDepsError"
        this.message = (message || "")
    }
}

export {
    BadInputError,
    BadSnykTestOutput,
    PrintDepsError
}