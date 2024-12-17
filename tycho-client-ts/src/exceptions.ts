export class TychoClientException extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TychoClientException";
  }
}

export class TychoStreamException extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TychoStreamException";
  }
}
