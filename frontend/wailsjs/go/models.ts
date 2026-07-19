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

export namespace main {
	
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
	export class DeviceLinkState {
	    pending: boolean;
	    fingerprint: string;
	
	    static createFrom(source: any = {}) {
	        return new DeviceLinkState(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.pending = source["pending"];
	        this.fingerprint = source["fingerprint"];
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
	    }
	}
	export class Verification {
	    safetyNumber: string;
	    status: string;
	    devices: number;
	
	    static createFrom(source: any = {}) {
	        return new Verification(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.safetyNumber = source["safetyNumber"];
	        this.status = source["status"];
	        this.devices = source["devices"];
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
	
	    static createFrom(source: any = {}) {
	        return new Conversation(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.screenName = source["screenName"];
	        this.messages = this.convertValues(source["messages"], Message);
	        this.unread = source["unread"];
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

