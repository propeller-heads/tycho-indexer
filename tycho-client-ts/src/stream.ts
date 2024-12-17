import { spawn, ChildProcessWithoutNullStreams } from "child_process";
import { Readable } from "stream";
import * as os from "os";
import * as path from "path";
import * as fs from "fs";
import { execSync } from "child_process";
import { Chain } from "./dto";
import { FeedMessage } from "./dto";
import { TychoStreamException } from "./exceptions";

interface TychoStreamConfig {
  tychoUrl: string;
  exchanges: string[];
  blockchain: Chain;
  authToken?: string;
  minTvl?: number;
  minTvlRange?: [number, number];
  includeState?: boolean;
  logsDirectory?: string;
  tychoClientPath?: string;
  useTls?: boolean;
}

export class TychoStream {
  private tychoClientProcess: ChildProcessWithoutNullStreams | null = null;
  private stream: Readable | null = null;
  private config: TychoStreamConfig;

  constructor(config: TychoStreamConfig) {
    this.config = {
      ...config,
      includeState: config.includeState ?? true,
      useTls: config.useTls ?? true,
      logsDirectory: config.logsDirectory || this.getDefaultLogDirectory(),
      tychoClientPath: config.tychoClientPath || this.findTychoClient(),
    };
  }

  private getDefaultLogDirectory(): string {
    let defaultDir: string;
    switch (os.platform()) {
      case "win32":
        defaultDir = path.join(
          process.env.APPDATA || "",
          "tycho-client",
          "logs"
        );
        break;
      case "darwin":
        defaultDir = path.join(os.homedir(), "Library", "Logs", "tycho-client");
        break;
      default:
        defaultDir = path.join(
          os.homedir(),
          ".local",
          "share",
          "tycho-client",
          "logs"
        );
        break;
    }

    fs.mkdirSync(defaultDir, { recursive: true });
    return defaultDir;
  }

  private findTychoClient(): string {
    try {
      return execSync("which tycho-client").toString().trim();
    } catch {
      throw new TychoStreamException("tycho-client not found in PATH");
    }
  }

  async start(): Promise<void> {
    const cmd = [
      "--log-folder",
      this.config.logsDirectory,
      "--tycho-url",
      this.config.tychoUrl,
    ];

    if (this.config.minTvl !== undefined) {
      cmd.push("--min-tvl", this.config.minTvl.toString());
    } else if (this.config.minTvlRange) {
      cmd.push(
        "--remove-tvl-threshold",
        this.config.minTvlRange[0].toString(),
        "--add-tvl-threshold",
        this.config.minTvlRange[1].toString()
      );
    }

    if (this.config.authToken) {
      cmd.push("--auth-key", this.config.authToken);
    }

    if (!this.config.includeState) {
      cmd.push("--no-state");
    }

    if (!this.config.useTls) {
      cmd.push("--no-tls");
    }

    this.config.exchanges.forEach((exchange) => {
      cmd.push("--exchange", exchange);
    });

    this.tychoClientProcess = spawn(this.config.tychoClientPath!, cmd, {
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, NO_COLOR: "true" },
    });

    try {
      this.tychoClientProcess = spawn(this.config.tychoClientPath!, cmd, {
        stdio: ["pipe", "pipe", "pipe"],
        env: { ...process.env, NO_COLOR: "true" },
      });

      if (!this.tychoClientProcess) {
        throw new TychoStreamException("Failed to start Tycho client process");
      }

      // Add error handling for stderr
      this.tychoClientProcess.stderr.on("data", (data) => {
        const errorMessage = data.toString();
        throw new TychoStreamException(`Tycho client error: ${errorMessage}`);
      });

      // Add error handling for process errors
      this.tychoClientProcess.on("error", (error) => {
        throw new TychoStreamException(`Process error: ${error.message}`);
      });

      // Add error handling for process exit
      this.tychoClientProcess.on("exit", (code) => {
        if (code !== 0) {
          throw new TychoStreamException(`Process exited with code ${code}`);
        }
      });

      this.stream = this.tychoClientProcess.stdout;
    } catch (error) {
      throw new TychoStreamException(
        `Error starting Tycho client process: ${error.message}`
      );
    }
  }

  async *[Symbol.asyncIterator]() {
    if (!this.stream) {
      throw new TychoStreamException("Stream not started");
    }

    let buffer = "";
    for await (const chunk of this.stream) {
      buffer += chunk.toString();
      const lines = buffer.split("\n");

      while (lines.length > 1) {
        const line = lines.shift()!;
        try {
          const msg = JSON.parse(line);
          yield this.processMessage(msg);
        } catch (error) {
          console.error(`Invalid JSON: ${line}`, error);
        }
      }

      buffer = lines[0] || "";
    }

    if (buffer.trim()) {
      try {
        const msg = JSON.parse(buffer);
        yield this.processMessage(msg);
      } catch (error) {
        console.error(`Invalid final JSON: ${buffer}`, error);
      }
    }
  }

  private processMessage(msg: any): FeedMessage {
    return msg as FeedMessage;
  }
}
