import { pbkdf2Sync } from 'crypto';

export function derive(password: string, salt: Buffer, rounds: number) {
  return pbkdf2Sync(password, salt, rounds, 32, 'sha256');
}

export function login(password: string, salt: Buffer) {
  return derive(password, salt, 10000);
}
