export namespace client {
	
	export class GroupInfo {
	    name: string;
	    count: number;
	
	    static createFrom(source: any = {}) {
	        return new GroupInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.count = source["count"];
	    }
	}

}

export namespace config {
	
	export class Theme {
	    name?: string;
	    tokens?: Record<string, string>;
	
	    static createFrom(source: any = {}) {
	        return new Theme(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.tokens = source["tokens"];
	    }
	}

}

export namespace e2ee {
	
	export class SafetyEmoji {
	    emoji: string;
	    name: string;
	
	    static createFrom(source: any = {}) {
	        return new SafetyEmoji(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.emoji = source["emoji"];
	        this.name = source["name"];
	    }
	}

}

export namespace main {
	
	export class ConnectionRequestInfo {
	    screenName: string;
	    reason: string;
	
	    static createFrom(source: any = {}) {
	        return new ConnectionRequestInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.screenName = source["screenName"];
	        this.reason = source["reason"];
	    }
	}
	export class DeviceInfo {
	    key: string;
	    fingerprint: string;
	    thisDevice: boolean;
	
	    static createFrom(source: any = {}) {
	        return new DeviceInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.fingerprint = source["fingerprint"];
	        this.thisDevice = source["thisDevice"];
	    }
	}
	export class IdentityState {
	    flow: string;
	    fingerprint: string;
	    devices: number;
	    issuedAt: number;
	    recoveryWords: number;
	
	    static createFrom(source: any = {}) {
	        return new IdentityState(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.flow = source["flow"];
	        this.fingerprint = source["fingerprint"];
	        this.devices = source["devices"];
	        this.issuedAt = source["issuedAt"];
	        this.recoveryWords = source["recoveryWords"];
	    }
	}
	export class Preferences {
	    theme: config.Theme;
	    soundEnabled: boolean;
	    soundPack: string;
	    mutedSounds: string[];
	    historyEnabled: boolean;
	    historyRetentionDays: number;
	    e2eeEnabled: boolean;
	    profile: string;
	    customFrame: boolean;
	    skinTone: number;
	
	    static createFrom(source: any = {}) {
	        return new Preferences(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.theme = this.convertValues(source["theme"], config.Theme);
	        this.soundEnabled = source["soundEnabled"];
	        this.soundPack = source["soundPack"];
	        this.mutedSounds = source["mutedSounds"];
	        this.historyEnabled = source["historyEnabled"];
	        this.historyRetentionDays = source["historyRetentionDays"];
	        this.e2eeEnabled = source["e2eeEnabled"];
	        this.profile = source["profile"];
	        this.customFrame = source["customFrame"];
	        this.skinTone = source["skinTone"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ProfilePreview {
	    screenName: string;
	    profile: string;
	    away: string;
	
	    static createFrom(source: any = {}) {
	        return new ProfilePreview(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.screenName = source["screenName"];
	        this.profile = source["profile"];
	        this.away = source["away"];
	    }
	}
	export class RecoveryKeyInfo {
	    recoveryKey: string;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new RecoveryKeyInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.recoveryKey = source["recoveryKey"];
	        this.error = source["error"];
	    }
	}
	export class RecoveryKeyStatus {
	    available: boolean;
	    created: number;
	    lastVerified: number;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new RecoveryKeyStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.available = source["available"];
	        this.created = source["created"];
	        this.lastVerified = source["lastVerified"];
	        this.error = source["error"];
	    }
	}
	export class RoomInviteInfo {
	    room: string;
	    from: string;
	
	    static createFrom(source: any = {}) {
	        return new RoomInviteInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.room = source["room"];
	        this.from = source["from"];
	    }
	}
	export class RoomSecurity {
	    encrypted: boolean;
	    readable: boolean;
	    nonReaders: string[];
	    members: string[];
	
	    static createFrom(source: any = {}) {
	        return new RoomSecurity(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.encrypted = source["encrypted"];
	        this.readable = source["readable"];
	        this.nonReaders = source["nonReaders"];
	        this.members = source["members"];
	    }
	}
	export class ServerSettings {
	    host: string;
	    port: number;
	    tls: boolean;
	    tlsInsecure: boolean;
	    lastScreenName: string;
	    remembered: boolean;
	    build: string;
	
	    static createFrom(source: any = {}) {
	        return new ServerSettings(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.host = source["host"];
	        this.port = source["port"];
	        this.tls = source["tls"];
	        this.tlsInsecure = source["tlsInsecure"];
	        this.lastScreenName = source["lastScreenName"];
	        this.remembered = source["remembered"];
	        this.build = source["build"];
	    }
	}
	export class Verification {
	    safetyNumber: string;
	    safetyEmoji: e2ee.SafetyEmoji[];
	    status: string;
	    devices: number;
	
	    static createFrom(source: any = {}) {
	        return new Verification(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.safetyNumber = source["safetyNumber"];
	        this.safetyEmoji = this.convertValues(source["safetyEmoji"], e2ee.SafetyEmoji);
	        this.status = source["status"];
	        this.devices = source["devices"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace state {
	
	export class Buddy {
	    screenName: string;
	    key: string;
	    group: string;
	    alias?: string;
	    presence: string;
	    awayMessage?: string;
	    profile?: string;
	    blocked?: boolean;
	    pending?: boolean;
	    iconHash?: string;
	    e2eeCapable?: boolean;
	    capsKnown?: boolean;
	    // Go type: time
	    idleSince: any;
	    // Go type: time
	    signedOnAt: any;
	
	    static createFrom(source: any = {}) {
	        return new Buddy(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.screenName = source["screenName"];
	        this.key = source["key"];
	        this.group = source["group"];
	        this.alias = source["alias"];
	        this.presence = source["presence"];
	        this.awayMessage = source["awayMessage"];
	        this.profile = source["profile"];
	        this.blocked = source["blocked"];
	        this.pending = source["pending"];
	        this.iconHash = source["iconHash"];
	        this.e2eeCapable = source["e2eeCapable"];
	        this.capsKnown = source["capsKnown"];
	        this.idleSince = this.convertValues(source["idleSince"], null);
	        this.signedOnAt = this.convertValues(source["signedOnAt"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Message {
	    from: string;
	    to: string;
	    text: string;
	    // Go type: time
	    at: any;
	    outgoing: boolean;
	    autoResponse?: boolean;
	    encrypted?: boolean;
	    senderVerified?: boolean;
	    forged?: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Message(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.from = source["from"];
	        this.to = source["to"];
	        this.text = source["text"];
	        this.at = this.convertValues(source["at"], null);
	        this.outgoing = source["outgoing"];
	        this.autoResponse = source["autoResponse"];
	        this.encrypted = source["encrypted"];
	        this.senderVerified = source["senderVerified"];
	        this.forged = source["forged"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Conversation {
	    key: string;
	    screenName: string;
	    messages: Message[];
	    unread: number;
	    hidden?: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Conversation(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.screenName = source["screenName"];
	        this.messages = this.convertValues(source["messages"], Message);
	        this.unread = source["unread"];
	        this.hidden = source["hidden"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class Room {
	    cookie: string;
	    name: string;
	    joined: boolean;
	    participants: string[];
	    messages: Message[];
	
	    static createFrom(source: any = {}) {
	        return new Room(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.cookie = source["cookie"];
	        this.name = source["name"];
	        this.joined = source["joined"];
	        this.participants = source["participants"];
	        this.messages = this.convertValues(source["messages"], Message);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Self {
	    screenName: string;
	    presence: string;
	    awayMessage?: string;
	    warningLevel: number;
	
	    static createFrom(source: any = {}) {
	        return new Self(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.screenName = source["screenName"];
	        this.presence = source["presence"];
	        this.awayMessage = source["awayMessage"];
	        this.warningLevel = source["warningLevel"];
	    }
	}

}

