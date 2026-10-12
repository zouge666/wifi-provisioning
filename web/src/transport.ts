// A way to send whole messages to the device and to wait for the next one.

export class TransportClosed extends Error {}
export class TransportTimeout extends Error {}

export interface Transport {
  send(message: Uint8Array): void;
  // The next message from the device. Waits at most timeoutMs.
  receive(timeoutMs: number): Promise<Uint8Array>;
  close(): void;
}

interface Waiter {
  resolve: (message: Uint8Array) => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

// Messages over a WebSocket. The protocol is binary, so text means something else is talking.
export class WebSocketTransport implements Transport {
  private readonly socket: WebSocket;
  private readonly queue: Uint8Array[] = [];
  private waiter: Waiter | null = null;
  private closed = false;

  private constructor(socket: WebSocket) {
    this.socket = socket;
    socket.binaryType = "arraybuffer";
    socket.onmessage = (event) => {
      if (!(event.data instanceof ArrayBuffer)) {
        this.end();
        return;
      }
      this.deliver(new Uint8Array(event.data));
    };
    socket.onclose = () => this.end();
    socket.onerror = () => this.end();
  }

  static open(url: string): Promise<WebSocketTransport> {
    return new Promise((resolve, reject) => {
      const socket = new WebSocket(url);
      socket.onopen = () => resolve(new WebSocketTransport(socket));
      socket.onerror = () => reject(new TransportClosed("could not connect to the device"));
      socket.onclose = () => reject(new TransportClosed("could not connect to the device"));
    });
  }

  send(message: Uint8Array): void {
    if (this.closed) {
      throw new TransportClosed("the connection is closed");
    }
    this.socket.send(new Uint8Array(message)); // a copy that the browser's types accept
  }

  receive(timeoutMs: number): Promise<Uint8Array> {
    const next = this.queue.shift();
    if (next !== undefined) {
      return Promise.resolve(next);
    }
    if (this.closed) {
      return Promise.reject(new TransportClosed("the connection is closed"));
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiter = null;
        reject(new TransportTimeout("the device did not answer in time"));
      }, timeoutMs);
      this.waiter = { resolve, reject, timer };
    });
  }

  close(): void {
    this.end();
    this.socket.close();
  }

  private deliver(message: Uint8Array): void {
    const waiter = this.waiter;
    if (waiter === null) {
      this.queue.push(message);
      return;
    }
    this.waiter = null;
    clearTimeout(waiter.timer);
    waiter.resolve(message);
  }

  private end(): void {
    this.closed = true;
    const waiter = this.waiter;
    if (waiter !== null) {
      this.waiter = null;
      clearTimeout(waiter.timer);
      waiter.reject(new TransportClosed("the connection is closed"));
    }
  }
}
