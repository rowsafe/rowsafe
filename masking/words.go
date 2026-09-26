package masking

// Word lists for fake values. Common, culturally mixed names; street and
// city names that don't point at anyone.

var firstNames = []string{
	"Olivia", "Liam", "Emma", "Noah", "Amelia", "Oliver", "Sophia", "Elijah", "Mia", "Lucas",
	"Isabella", "Mateo", "Ava", "Levi", "Harper", "Ethan", "Luna", "James", "Ella", "Leo",
	"Aria", "Kai", "Nora", "Aiden", "Zoe", "Ezra", "Layla", "Hugo", "Chloe", "Omar",
	"Sofia", "Yusuf", "Hana", "Arjun", "Priya", "Chen", "Mei", "Kenji", "Yuki", "Diego",
	"Lucia", "Mohammed", "Fatima", "Ali", "Aisha", "Ivan", "Anya", "Luca", "Giulia", "Pierre",
	"Camille", "Jonas", "Lena", "Mateus", "Ana", "Kwame", "Amara", "Tariq", "Leila", "Sven",
	"Freya", "Rafael", "Elena", "Tomas", "Clara", "Nikolai", "Maya", "Samuel", "Grace", "Daniel",
	"Ruby", "David", "Alice", "Adam", "Iris", "Felix", "Ivy", "Oscar", "Nina", "Max",
	"Eva", "Theo", "Rosa", "Jin", "Seo-yeon", "Ravi", "Anika", "Kofi", "Zara", "Emil",
	"Ines", "Pablo", "Carmen", "Idris", "Noor", "Soren", "Astrid", "Marco", "Bianca", "Sami",
}

var lastNames = []string{
	"Martin", "Smith", "Garcia", "Johnson", "Nguyen", "Kim", "Brown", "Rossi", "Muller", "Silva",
	"Lopez", "Williams", "Tanaka", "Wang", "Li", "Khan", "Patel", "Ahmed", "Ivanova", "Novak",
	"Jones", "Miller", "Davis", "Rodriguez", "Martinez", "Hernandez", "Wilson", "Anderson", "Taylor", "Thomas",
	"Moore", "Jackson", "White", "Harris", "Clark", "Lewis", "Walker", "Hall", "Young", "Allen",
	"King", "Wright", "Scott", "Green", "Baker", "Adams", "Nelson", "Hill", "Campbell", "Mitchell",
	"Roberts", "Carter", "Phillips", "Evans", "Turner", "Torres", "Parker", "Collins", "Edwards", "Stewart",
	"Morris", "Murphy", "Cook", "Rogers", "Morgan", "Peterson", "Cooper", "Reed", "Bailey", "Bell",
	"Gomez", "Kelly", "Howard", "Ward", "Cox", "Diaz", "Richardson", "Wood", "Watson", "Brooks",
	"Bennett", "Gray", "James", "Reyes", "Cruz", "Hughes", "Price", "Myers", "Long", "Foster",
	"Sanders", "Ross", "Morales", "Powell", "Sullivan", "Russell", "Ortiz", "Jenkins", "Perry", "Fischer",
}

var streetNames = []string{
	"Maple", "Oak", "Cedar", "Pine", "Elm", "Willow", "Birch", "Aspen", "Chestnut", "Juniper",
	"Hillside", "Lakeview", "Riverside", "Meadow", "Orchard", "Sunset", "Harbor", "Prospect", "Park", "Mill",
	"Church", "Station", "Bridge", "Garden", "Forest", "Valley", "Spring", "Highland", "Grove", "Brook",
}

var streetKinds = []string{"Street", "Avenue", "Road", "Lane", "Drive", "Way", "Court", "Place", "Terrace", "Boulevard"}

var cities = []string{
	"Riverton", "Fairview", "Lakewood", "Brookfield", "Maplewood", "Cedar Falls", "Oakridge", "Springdale", "Westbury", "Northfield",
	"Eastwick", "Hillcrest", "Greenville", "Ashford", "Kingsport", "Milltown", "Stonebridge", "Clearwater", "Pinehurst", "Glenwood",
	"Harborview", "Silverton", "Meadowbrook", "Redcliff", "Bayside", "Elmhurst", "Rosedale", "Windham", "Foxborough", "Summerfield",
}

var loremWords = []string{
	"lorem", "ipsum", "dolor", "sit", "amet", "consectetur", "adipiscing", "elit", "sed", "do",
	"eiusmod", "tempor", "incididunt", "ut", "labore", "et", "dolore", "magna", "aliqua", "enim",
	"ad", "minim", "veniam", "quis", "nostrud", "exercitation", "ullamco", "laboris", "nisi", "aliquip",
	"ex", "ea", "commodo", "consequat", "duis", "aute", "irure", "in", "reprehenderit", "voluptate",
	"velit", "esse", "cillum", "fugiat", "nulla", "pariatur", "excepteur", "sint", "occaecat", "cupidatat",
}
