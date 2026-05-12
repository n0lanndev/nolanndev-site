---
title: Construire un Packer & Loader PE de A à Z
date: 2026-05-12
tags: ["C++", "Windows Internals", "Cybersecurity", "Reverse Engineering"]
categories: ["Système", "Sécurité"]
toc: true
---

Bienvenue dans ce guide. Nous allons apprendre à créer un Packer, un outil capable de chiffrer un programme Windows (.exe) et de le charger directement en mémoire sans qu'il ne touche jamais le disque.
> Note : Ce contenu est à but purement éducatif. Voir l'avertissement complet en [fin d'article](#disclaimer).

## Théorie : Comment Windows lance-t-il un programme ? {#theorie}

Pour construire un loader, il faut d'abord comprendre ce qu'est réellement un fichier .exe. Sous Windows, on utilise le format PE (*Portable Executable*).

Un fichier PE n'est pas simplement une suite d'instructions machine : c'est une structure normalisée contenant toutes les informations nécessaires au système pour charger le programme en mémoire, résoudre ses dépendances, appliquer ses protections mémoire et enfin exécuter son point d'entrée.

Pour nous guider, nous allons utiliser la carte de référence absolue : le Dissected PE :

{{< image src="/img/packer/pefile.png" alt="Anatomie d'un fichier PE" >}}
Figure 1 : Anatomie d'un fichier PE  
Source : https://onlyf8.com/pe-format
{{< /image >}}

### Vue d'ensemble : ce que fait Windows quand on double-clique sur un .exe

Lorsqu'un utilisateur lance un programme, Windows ne "lit pas juste le fichier puis exécute le code". Il suit en réalité plusieurs étapes précises :
1. Ouvre le fichier sur disque
2. Vérifie qu'il s'agit bien d'un exécutable PE valide
3. Réserve un espace mémoire pour l'image du programme
4. Copie les différentes sections (.text, .data, .rdata, etc.) en mémoire
5. Charge les DLL nécessaires (kernel32.dll, user32.dll, ...)
6. Résout les imports (CreateFileA, MessageBoxA, etc.)
7. Applique les relocations si l'image n'est pas chargée à son adresse préférée
8. Configure les protections mémoire (RX, RW, etc.)
9. Lance le point d'entrée (EntryPoint)

### Anatomie d'un fichier PE

L'image montre qu'un exécutable Windows est divisé en plusieurs blocs logiques :

**Headers** : métadonnées décrivant le programme
**Sections** : contenu réel (code, données, ressources...)
**Imports** : fonctions externes utilisées
**Relocations** : ajustements d'adresses mémoire
**Entry Point** : première instruction exécutée

Voyons cela proprement.

### 1. Le DOS Header :

Tout fichier PE commence par deux octets célèbres :
```cpp
4D 5A
```
Ce sont les caractères :
```cpp
MZ
```
Signature historique des exécutables MS-DOS.

Le champ le plus important ici est :

```cpp
e_lfanew
```

Il contient l'offset du vrai header PE dans le fichier.

En clair :
> Windows lit d'abord le header DOS, puis saute à e_lfanew pour trouver la structure moderne.

### 2. Le PE Header : identité du programme

À l'offset indiqué par e_lfanew, on trouve :

```cpp
50 45 00 00
```

Soit :

```cpp
PE\0\0
```

C'est la signature officielle du format Portable Executable.

Ensuite viennent plusieurs champs importants :

#### Machine

Malgré son nom, ce champ ne désigne pas "l’ordinateur", mais
l’architecture processeur visée par le binaire.

- **0x14C**   -> x86 (32 bits)
- **0x8664**  -> x64
- **0xAA64**  -> ARM64

#### NumberOfSections

Nombre de sections présentes (.text, .data, etc.)

#### SizeOfOptionalHeader

Taille, en octets, du header suivant :

```cpp
IMAGE_OPTIONAL_HEADER
```

Ce champ permet à Windows de savoir où commence la table des sections juste après.

Valeurs classiques :

```cpp
0xE0 -> PE32
0xF0 -> PE32+ (x64)
```

#### Characteristics

Champ de flags décrivant la nature du fichier.

Exemples :

* exécutable (*EXE*)
* bibliothèque dynamique (*DLL*)
* 32 bits
* gros fichier sans symboles
* relocs supprimées
* etc.

C’est en quelque sorte la carte d’identité du binaire.

### 3. Optional Header (qui n'est pas optionnel)

Malgré son nom, cette structure est indispensable.

Elle contient les paramètres de chargement les plus importants :

#### ImageBase

Adresse mémoire préférée du programme :

```cpp
0x140000000
```

#### AddressOfEntryPoint

Offset de la première instruction à exécuter.

#### SizeOfImage

Taille totale occupée en mémoire après chargement.

#### SectionAlignment / FileAlignment

Règles d'alignement :
- Sur disque
- En mémoire

Très important lors d'un packer ou d'une reconstruction manuelle.

### 4. Les Data Directories

* **Import Table** *(La liste de courses)* : Contient les noms des fonctions externes et des DLL dont le programme a besoin pour fonctionner (ex: CreateFileA dans kernel32.dll).
* **Export Table** *(Le menu des services)* : Utilisée principalement par les DLL pour lister les fonctions qu'elles mettent à disposition des autres programmes.
* **Relocation Table** *(Le plan de secours)* : Liste les endroits du code où Windows doit ajuster les adresses mémoires si le programme n'est pas chargé à sa place préférée (indispensable pour l'ASLR).
* **TLS - Thread Local Storage** *(Le casier personnel)* : Zone de mémoire réservée pour des variables qui sont propres à chaque "Thread" (fil d'exécution) du programme.
* **Resources** *(Le coffre à jouets)* : Contient tout ce qui n'est pas du code : les icônes du programme, les images, les menus, les boîtes de dialogue ou même des fichiers embarqués.
* **Exception Table** *(Le filet de sécurité)* : Contient une liste de tables de gestion d'erreurs. Elle permet au système de savoir quoi faire si le programme plante (essentiel sur les architectures 64 bits).
* **Debug Directory** *(Le carnet de notes)* : Contient des informations sur la manière dont le programme a été compilé et où se trouvent les fichiers de symboles (.pdb) pour le débogage.
* **Load Config Directory** *(Les consignes de sécurité)* : Contient des paramètres de sécurité avancés, comme la configuration du Control Flow Guard (CFG) qui protège contre l'exploitation de failles.
* **IAT - Import Address Table** *(Le tableau de branchement)* : C'est la table réelle où Windows écrit les adresses mémoires finales des fonctions importées une fois que le programme est lancé.

### Les sections : le vrai contenu du programme

Après les headers viennent les sections.

Chaque section possède :
* un nom
* une adresse virtuelle
* une taille
* des permissions mémoire

Les plus courantes :

#### .text

Contient le code machine du programme.

Permissions :
```cpp
READ + EXECUTE
```
C'est ici que se trouvent les instructions CPU.

#### .data

Variables globales modifiables :
```cpp
int compteur = 0;
char flag = 1;
```
Permissions :
```cpp
READ + WRITE
```
#### .rdata

Données constantes :

- chaînes statiques
- tables virtuelles C++
- imports parfois

Permissions :
```cpp
READ ONLY
```

#### .rsrc

Icônes, menus, version info, manifestes.

#### .reloc

Table des relocations.

Utilisée si le programme n'est pas chargé à ImageBase.

### Les Imports : parler avec Windows

Un **.exe** n'embarque pas tout Windows.

Quand un programme appelle :

```cpp
MessageBoxA(...)
CreateFileA(...)
VirtualAlloc(...)
```
Ces fonctions viennent de DLL externes :
* user32.dll
* kernel32.dll
* ntdll.dll

Le fichier PE contient donc une Import Table listant :
* la DLL à charger
* les fonctions nécessaires

Le chargeur Windows remplit ensuite l'IAT *(Import Address Table)* avec les vraies adresses mémoire.

Notre futur loader devra refaire cela lui-même.

### Les Relocations : déplacer le programme

Supposons que le binaire souhaite être chargé ici :
```cpp
0x140000000
```
Mais cette zone mémoire est déjà occupée.

Windows le charge ailleurs :
```cpp
0x7FF600000000
```
Certaines adresses codées en dur deviennent fausses.
Le loader parcourt alors .reloc et corrige automatiquement les pointeurs.
C'est indispensable pour un manual mapping fiable.

### Le Point d'entrée : naissance du processus

Quand tout est prêt :

* sections copiées
* imports résolus
* relocations appliquées
* protections mémoire actives

Windows saute vers :
```cpp
EntryPoint
```

Sur un programme C/C++, ce n'est souvent pas **main()** directement.

On passe généralement par le runtime CRT :

```cpp
mainCRTStartup()
```

Qui initialise :
- heap
- variables globales
- TLS
- constructeurs C++

Puis appelle enfin :
```cpp
main()
```

### Pourquoi tout cela nous intéresse pour un packer ?

Un packer transforme un exécutable en données compressées ou chiffrées.

Ensuite un stub/loader doit :

1. Déchiffrer le payload
2. Recréer une image PE en mémoire
3. Résoudre imports et relocations
4. Exécuter le point d'entrée

Autrement dit :
> Créer un packer revient à réécrire une version miniature du chargeur de Windows.

## Le Packer : Transformer un .exe en données chiffrées. {#packer}

Maintenant que nous comprenons la structure d’un fichier PE, nous pouvons passer à la première étape pratique : transformer un exécutable en payload embarqué.

L’objectif d’un packer est simple :

1. Lire un programme .exe brut
2. Chiffrer ses octets
3. Convertir le résultat en tableau C++
4. Intégrer ce tableau dans un loader

Ainsi, le binaire original n’apparaît plus clairement sur disque.

### Lecture du fichier source

Notre packer ouvre l’exécutable en mode binaire :

```cpp
std::ifstream file(filename, std::ios::binary | std::ios::ate);
```
* **std::ios::binary** : On force la lecture brute. Sans cela, le programme pourrait interpréter certains octets comme des caractères spéciaux (fin de ligne, etc.), ce qui corromprait le .exe.
* **std::ios::ate** : "At The End". On ouvre le fichier et on place le curseur de lecture immédiatement à la fin.

#### Récupérer la taille exacte
Une fois le fichier ouvert à la fin, nous voulons récupérer : "À quelle distance du début se trouve-t-on?". C'est le rôle de **tellg()** :
```cpp
std::streamsize size = file.tellg();
```
La valeur de size correspond alors précisément au nombre d'octets du fichier. Avant de lire, il ne faut pas oublier de rembobiner le curseur au début avec :
```cpp
file.seekg(0, std::ios::beg);
```
sinon la lecture commencera... à la fin, et on ne récupérera rien.

#### Le passage en mémoire

Une fois qu'on connaît la taille du fichier, il faut créer un espace en mémoire (la RAM) pour l'accueillir. On utilise pour cela un **std::vector<uint8_t>**.

C'est le conteneur idéal pour un packer car :
* Dynamique : Il s'ajuste exactement à la taille **size** de l'exécutable.
* Brut : Le type **uint8_t** garantit que chaque case fait exactement 1 octet (8 bits). C’est l’unité de mesure universelle pour manipuler des données binaires sans interprétation de texte.

##### Le transfert des données

Pour copier le contenu du fichier dans notre vecteur, on utilise la méthode **.read()** :
```cpp
// 1. On réserve l'espace nécessaire dans la RAM
std::vector<uint8_t> buffer(static_cast<size_t>(size));

// 2. On recopie le fichier vers cet espace
file.read(reinterpret_cast<char *>(buffer.data()), size);
```
> Pourquoi le **reinterpret_cast** ?
La fonction **read** de la bibliothèque standard est un peu ancienne : elle s'attend à manipuler des caractères (**char**). Or, nous manipulons des octets bruts (**uint8_t**). On utilise donc **reinterpret_cast** pour dire au compilateur : "Ne t'inquiète pas, traite ce bloc de mémoire comme s'il contenait des caractères pour la lecture, même si ce sont des octets."

À cette étape précise, l'exécutable n'est plus seulement un fichier figé sur votre disque dur. Il est devenu un tableau d'octets vivant dans la RAM. Chaque octet du programme original est maintenant accessible via buffer[i], prêt à subir une transformation mathématique (comme notre chiffrement XOR).

### Chiffrement XOR
Pour cette démonstration, nous utilisons un XOR simple :
```cpp
constexpr uint8_t XOR_KEY = 0x5A;
```
Chaque octet du fichier est transformé :
```cpp
byte ^= XOR_KEY;
```
Le XOR possède une propriété mathématique : il est symétrique. Si vous appliquez la clé une deuxième fois, vous retrouvez la valeur d'origine.
```cpp
A ^ K ^ K = A
```
Cela signifie que le code que nous utilisons pour "packer" le fichier sera exactement le même que celui utilisé par le "loader" pour le déchiffrer en mémoire.

Exemple :
| Octet original | Clé    | Résultat |
| -------------- | ------ | -------- |
| `0x4D`         | `0x5A` | `0x17`   |
| `0x17`         | `0x5A` | `0x4D`   |
| `0x5A`         | `0x5A` | `0x00`   |

>Note sur la sécurité :
Le XOR avec une clé unique de 1 octet est un chiffrement très faible. Un analyste pourrait retrouver la clé en quelques secondes (via une analyse de fréquence ou en connaissant les premiers octets habituels d'un fichier PE).
Ici, l'objectif est pédagogique : le but est de comprendre la logique de transformation des données et le fonctionnement d'un packer, pas de créer un algorithme inviolable. Dans un outil professionnel, on utiliserait des algorithmes plus complexes comme l'AES.

### Génération du header C++
Une fois chiffré, le payload est exporté sous forme de fichier :
```cpp
payload.h
```
Contenant :
```cpp
#pragma once
#include <cstdint>

inline constexpr std::size_t payload_size = 69120;
inline constexpr std::uint8_t payload[] = {
    0x17, 0x00, 0xca, ...
};
```
* **constexpr** : Indique au compilateur que la valeur est immuable et déterminée dès la compilation. Pour notre payload, cela signifie que le tableau d'octets est gravé directement dans le binaire du loader de façon statique. Le compilateur peut ainsi optimiser l'accès à ces données puisqu'il sait qu'elles ne changeront jamais pendant l'exécution.
> Différence avec **const**
Le mot-clé **const** signifie que la variable est en lecture seule après avoir été initialisée. Cependant, cette initialisation peut se faire au moment où le programme tourne (**Runtime**).
**Exemple** : Tu demandes à l'utilisateur de taper un nombre, et tu le stockes dans un **const int**. La valeur est fixée, mais seulement une fois que l'utilisateur a appuyé sur Entrée.
* **inline** : C'est essentiel ici. Comme ce header peut être inclus dans plusieurs fichiers de notre projet, inline évite les erreurs de "redéfinition" (duplicate symbols) au moment du linkage. Cela permet de définir la variable directement dans le header sans créer de conflit.
> Si vous ne comprenez pas bien l'importance de inline, je vous recommande vivement cette vidéo qui explique son fonctionnement technique et pourquoi il est indispensable pour éviter les erreurs de linkage : [C++ - Le fonctionnement des includes et du mot-clé inline](https://www.youtube.com/watch?v=V7tRfMYemTA)

Le loader pourra inclure directement ce fichier :
```cpp
#include "payload.h"
```
#### Résultat final

Nous passons donc de par exemple:
```cpp
calc.exe
```
à :
```cpp
payload.h
```
contenant uniquement des octets chiffrés ainsi que la taille exacte du fichier, prêts à être chargés.

## Le Manual Mapping : Recréer le chargeur de Windows. {#manual-mapping}
Une fois le payload déchiffré et chargé en mémoire, il ne peut toujours pas être exécuté directement.
Pourquoi ?
Parce qu’un fichier PE sur disque n’est pas utilisable tel quel en mémoire. Il doit être reconstruit exactement comme Windows le ferait :
* allocation d’une image mémoire complète
* copie des headers
* copie des sections
* préparation pour la résolution des imports

C’est exactement le rôle du **manual mapping** : simuler manuellement ce que fait le loader de Windows.

### 1. Charger et restaurer le PE
On commence par copier le payload en mémoire :
```cpp
uint8_t *localCopy = new uint8_t[rawSize];
std::memcpy(localCopy, rawData, rawSize);
```
Puis on déchiffre le binaire :
```cpp
xorDecryptPayload(localCopy, rawSize, XOR_KEY);
```
À ce stade :
* on a un PE "vivant" en RAM
* mais encore non validé structurellement

### 2. Validation du format PE
Avant toute manipulation, on vérifie les signatures classiques du format Portable Executable.

**DOS header (MZ)**
```cpp
IMAGE_DOS_HEADER *dosHeader = reinterpret_cast<IMAGE_DOS_HEADER *>(localCopy);

if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
```

**NT header (PE\0\0)**
```cpp
IMAGE_NT_HEADERS *ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS *>(localCopy + dosHeader->e_lfanew);

if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
```
Si une de ces signatures est invalide :
* le fichier n’est pas un PE
* on stoppe immédiatement

### 3. Allocation de l’image en mémoire
On réserve un espace mémoire équivalent à celui que le programme occupera une fois chargé :
```cpp
SIZE_T sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
SIZE_T sizeOfHeader = ntHeaders->OptionalHeader.SizeOfHeaders;
```
Puis tentative d’allocation à l’adresse préférée du binaire :
```cpp
BYTE *baseAlloc = reinterpret_cast<BYTE *>(
    VirtualAlloc(
        reinterpret_cast<LPVOID>(ntHeaders->OptionalHeader.ImageBase),
        sizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE));
```
Si l’adresse préférée (**ImageBase**) est déjà occupée :
```cpp
if (!baseAlloc)
{
    baseAlloc = reinterpret_cast<BYTE *>(
        VirtualAlloc(
            nullptr,
            sizeOfImage,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE));
}
```
On demande alors à **VirtualAlloc** d’allouer l’image à une adresse libre choisie automatiquement par Windows dans l’espace mémoire disponible du processus.

Cette allocation représente le comportement idéal du loader lorsqu’aucun conflit mémoire n’existe. En pratique, l’ASLR ou d’autres allocations peuvent forcer Windows à charger l’image à une adresse différente, nécessitant alors une étape de relocation.

### 4. Copie des headers
On copie la structure PE telle quelle en mémoire :
```cpp
std::memcpy(baseAlloc, localCopy, sizeOfHeader);
```

### 5. Copie des sections
On récupère la table des sections :
```cpp
PIMAGE_SECTION_HEADER sectionHeaders = IMAGE_FIRST_SECTION(ntHeaders);
```
Puis on copie chaque section dans l’image allouée :
```cpp
for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
{
    // dest (mémoire) -> emplacement final en RAM
    BYTE *dest = baseAlloc + sectionHeaders[i].VirtualAddress;
    //src (fichier) -> données brutes sur disque
    BYTE *src  = localCopy + sectionHeaders[i].PointerToRawData; 
    DWORD size = sectionHeaders[i].SizeOfRawData;

    if (sectionHeaders[i].PointerToRawData + size > rawSize)
    {
        std::cerr << "[!] Section " << i << " dépasse la taille brute du payload.\n";

        VirtualFree(baseAlloc, 0, MEM_RELEASE);
        delete[] localCopy;
        return nullptr;
    }

    std::memcpy(dest, src, size);
}
```
Dans une implémentation plus robuste, il faut également prendre en compte VirtualSize, car certaines sections sont plus grandes en mémoire que sur disque.

## Les Relocations : étape d’extension {#relocations}

Les relocations ont déjà été présentées dans la partie théorie : elles servent à corriger les adresses internes du programme lorsque celui-ci n’est pas chargé à son **ImageBase** d’origine.

Dans une implémentation complète, cette étape repose sur la **Base Relocation Table**, qui contient des blocs d’adresses à ajuster en fonction du delta entre l’ImageBase souhaité et l’adresse réellement allouée en mémoire.

Dans notre cas, cette partie est volontairement laissée hors du périmètre de ce loader afin de garder une architecture simple et centrée sur les mécanismes principaux (mapping, imports, exécution).

> Cette étape constitue une extension naturelle pour un loader plus robuste et compatible avec davantage de binaires.

## Les Imports : Apprendre à parler avec les DLL système. {#imports}
Jusqu’ici, nous avons réussi à reconstruire l’image PE en mémoire et à copier ses sections. Mais un programme Windows ne vit jamais seul : il dépend presque toujours de fonctions externes fournies par les DLL système.

C’est exactement le rôle de la Import Table : dire au système "j’ai besoin de ces fonctions-là pour fonctionner".

Notre job dans un loader manuel est donc simple en théorie, mais délicat en pratique :

Charger les DLL nécessaires, puis remplacer les pointeurs d’imports par les vraies adresses mémoire des fonctions.

### Le principe des imports dans un PE
Quand un programme appelle par exemple :
```cpp
MessageBoxA(NULL, "Hello", "Test", 0);
```
Il ne contient pas directement le code de MessageBoxA.
À la place, le compilateur laisse une "place vide" dans une table appelée :
* **IAT** (*Import Address Table*) -> adresses finales des fonctions
* **INT** (*Import Name Table*) -> noms des fonctions utilisées

#### À quoi sert l’INT ?

**L’INT** (*Import Name Table*) sert juste à dire :
> "Voici les noms des fonctions que je veux utiliser"

Exemples :
* CreateFileA
* MessageBoxA
* VirtualAlloc

#### Concrètement

Quand Windows charge un programme :

1. Il lit **l’INT**
2. Il voit les noms des fonctions
3. Il va les chercher dans les DLL
4. Il remplit **l’IAT** avec leurs adresses

Dans cette version pédagogique, nous nous limitons aux imports résolus par nom afin de garder une implémentation lisible. Les imports par ordinal, bien que présents dans certains binaires système, ne sont pas traités ici.

### Lecture de la Import Table
Le point d’entrée de notre résolution d’imports commence ici :
```cpp
IMAGE_DATA_DIRECTORY &importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
```
Cette structure nous donne :
> l’adresse et la taille de la table des imports dans le PE

Si elle est vide :
```cpp
if (!importDir.VirtualAddress)
{
    return true;
}
```
Cela signifie simplement :
> le programme n’a aucune dépendance externe -> rien à faire

### Parcours des DLL importées

On récupère ensuite la première entrée :

```cpp
IMAGE_IMPORT_DESCRIPTOR *importDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR *>(baseAddress + importDir.VirtualAddress);
```
Chaque **IMAGE_IMPORT_DESCRIPTOR** représente une DLL.
On boucle tant qu’il y a des DLL :
```cpp
while (importDesc->Name)
```
### Chargement de la DLL
On récupère le nom de la DLL :
```cpp
LPCSTR dllName = reinterpret_cast<LPCSTR>(baseAddress + importDesc->Name);
```
Exemples possibles :
* kernel32.dll
* user32.dll
* ntdll.dll

Puis on la charge en mémoire :
```cpp
HMODULE hMod = LoadLibraryA(dllName);
```
À ce stade :
* la DLL est mappée dans le processus
* ses fonctions deviennent accessibles

Si le chargement échoue :
```cpp
if (!hMod)
{
    std::cerr << "[!] Echec LoadLibraryA : " << dllName << std::endl;
    return false;
}
```

### Les deux tables critiques : OriginalFirstThunk vs FirstThunk
C’est ici que les choses deviennent importantes.
```cpp
IMAGE_THUNK_DATA *thunkRef = reinterpret_cast<IMAGE_THUNK_DATA *>(baseAddress + importDesc->OriginalFirstThunk);
IMAGE_THUNK_DATA *funcRef = reinterpret_cast<IMAGE_THUNK_DATA *>(baseAddress + importDesc->FirstThunk);
```
**OriginalFirstThunk** (*INT*)
* Contient les noms des fonctions
* Sert uniquement de référence

**FirstThunk** (*IAT*)
* Contient les adresses finales
* C’est ce que le programme utilise réellement à l’exécution

#### Cas particulier
Certains binaires n’ont pas **OriginalFirstThunk** :

```cpp
if (!importDesc->OriginalFirstThunk)
{
    thunkRef = reinterpret_cast<IMAGE_THUNK_DATA *>(baseAddress + importDesc->FirstThunk);
}
```
Dans ce cas :
* la table des noms et la table des pointeurs sont confondues
* solution alternative nécessaire

### Résolution des fonctions

On parcourt chaque fonction importée :
```cpp
while (thunkRef->u1.AddressOfData)
```
Pour chaque entrée :

#### 1. Récupération de la structure "import by name"
```cpp
IMAGE_IMPORT_BY_NAME *importByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME *>(baseAddress + thunkRef->u1.AddressOfData);
```
Elle contient simplement :
```cpp
importByName->Name
```
Exemple :
```cpp
"CreateFileA"
"VirtualAlloc"
"MessageBoxA"
```

#### 2. Résolution de l’adresse réelle
```cpp
FARPROC *funcAddr = reinterpret_cast<FARPROC *>(&funcRef->u1.Function);
*funcAddr = GetProcAddress(hMod, importByName->Name);
```
Ici on fait le cœur du loader :
* on demande à Windows : où est cette fonction dans la DLL ?
* GetProcAddress retourne son adresse mémoire réelle
* on écrit cette adresse dans l’IAT

#### 3. Gestion des erreurs
```cpp
if (!*funcAddr)
{
    std::cerr << "[!] Impossible de résoudre l'import : " << dllName << std::endl;
    return false;
}
```
Si une fonction est introuvable :
* DLL corrompue
* version incompatible
* export absent

Le chargement échoue.

#### 4. Avancement des pointeurs
```cpp
thunkRef++;
funcRef++;
```
On passe simplement à l’entrée suivante.

### Fin de traitement d’une DLL
Quand toutes les fonctions d’une DLL sont résolues :
```cpp
importDesc++;
```
On passe à la DLL suivante.

### Résultat final

Si tout s’est bien passé :
```cpp
return true;
```
À ce stade :
* toutes les DLL sont chargées
* toutes les fonctions sont résolues
* **l’IAT** est entièrement valide

Le programme peut désormais s’exécuter comme s’il avait été lancé normalement par Windows.

## Le Point d’entrée : lancement du programme {#entrypoint}

Une fois toutes les étapes précédentes terminées :
* image reconstruite en mémoire
* sections copiées
* imports résolus
* relocations appliquées (si nécessaire)

le programme est enfin prêt à s’exécuter.

Le point d’entrée est défini dans le header PE :
```cpp
AddressOfEntryPoint
```
Il correspond à un offset relatif à la base de l’image chargée en mémoire.

### Ce que ça signifie

Contrairement à une idée simple, un programme Windows ne démarre pas directement sur **main()**.

Le flux réel est :

```cpp
EntryPoint -> runtime C/C++ -> mainCRTStartup -> main()
```

#### Rôle du loader

Dans un loader manuel, le rôle final est simplement de :
> transférer l’exécution vers cet EntryPoint

À partir de ce moment :
* le programme devient autonome
* il s’exécute comme s’il avait été lancé normalement

#### Résumé du pipeline complet
```cpp
Loader -> reconstruction -> imports -> relocations -> EntryPoint -> programme
```

## Anti-Tampering : Protéger notre code contre l'analyse. {#anti-tampering}

Une fois le programme chargé, nous voulons le protéger contre toute modification en cours d’exécution. Pour cela, notre loader met en place une simple surveillance de l’intégrité mémoire via un **CRC32**. Le principe :

### Calcul du CRC initial
Après avoir obtenu baseAlloc, on détermine **sizeOfImage** et on calcule un **CRC32** sur toute l’image :
```cpp
uint32_t initialChecksum = crc32(baseAlloc, sizeOfImage);
```
La fonction **crc32** parcourt chaque octet et applique l’algorithme standard (polynôme **0xEDB88320**) :

```cpp
uint32_t crc32(const uint8_t* data, size_t size) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < size; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 * (crc & 1));
        }
    }
    return ~crc;
}
```
Ce calcul produit une empreinte « numérique » de l’image chargée.
### Thread de surveillance

#### Pourquoi CRC32 ?
**CRC32** signifie :
```cpp
Cyclic Redundancy Check 32 bits
```
C’est un algorithme très rapide qui transforme un bloc mémoire en une valeur de **32 bits**.

Exemple :

```cpp
Zone mémoire A -> 0x91AF22BC
```
Si un seul octet change :

```cpp
Zone mémoire A modifiée -> 0x4D880012
```
Le résultat devient totalement différent.

Cela permet donc de détecter :
* patch mémoire
* hook
* injection
* corruption
* modification manuelle

##### Pourquoi pas SHA256 ?

On pourrait utiliser un hash cryptographique moderne comme :
* SHA1
* SHA256
* BLAKE2

Mais ici ce n’est pas nécessaire.

Notre objectif n’est pas de signer des données ni de résister à un attaquant cryptographique.

Nous voulons simplement :
* recalculer vite
* comparer vite

**CRC32** est donc idéal car il est :
* beaucoup plus rapide
* léger à implémenter
* suffisant pour une surveillance mémoire simple

> Cette approche est volontairement simple et sert uniquement à illustrer le concept de surveillance d’intégrité mémoire. Des implémentations réelles utilisent généralement des mécanismes plus complexes et distribués.

#### Comment fonctionne notre implémentation ?

Au lancement du programme :
1. Le loader calcule le **CRC32** de l’image PE chargée en mémoire
2. Il stocke cette valeur comme référence
3. Un thread secondaire tourne en arrière-plan
4. Toutes les quelques secondes, il recalcule le **CRC32**
5. Si la valeur change : arrêt immédiat du processus

C’est une forme simple d’auto-surveillance mémoire.

##### Implémentation
On crée un thread détaché qui tourne en arrière-plan et recalcule périodiquement le **CRC** :

```cpp
std::thread(AntiTamperThread, baseAlloc, sizeOfImage, initialChecksum).detach();
```
La fonction **AntiTamperThread** ressemble à :

```cpp
void AntiTamperThread(BYTE* baseAddress, SIZE_T sizeOfImage, uint32_t initialChecksum) {
    while (true) {
        uint32_t currentChecksum = crc32(baseAddress, sizeOfImage);
        if (currentChecksum != initialChecksum) {
            std::cerr << "Modification détecte\n";
            ExitProcess(0);
        }
        std::this_thread::sleep_for(std::chrono::seconds(3));
    }
}
```

##### Explication ligne par ligne
**Boucle infinie**

```cpp
while (true)
```
Le thread surveille continuellement la mémoire tant que le programme tourne.

**Recalcul du checksum**
```cpp
uint32_t currentChecksum = crc32(baseAddress, sizeOfImage);
```

On relit toute l’image PE chargée en mémoire :
* code .text
* données
* imports patchés
* sections copiées

Puis on calcule une nouvelle empreinte **CRC32**.

**Comparaison**
```cpp
if (currentChecksum != initialChecksum)
```

Si la nouvelle valeur diffère de l’originale :
> quelque chose a changé en mémoire.

**Réaction**
```cpp
ExitProcess(0);
```
Le programme se ferme immédiatement.

**Pause entre deux scans**
```cpp
sleep_for(3 secondes)
```
Cela évite de monopoliser le **CPU**.

Le contrôle est périodique, léger, discret.

##### Limites de cette approche

Cette protection reste volontairement simple.

Un analyste expérimenté pourrait :
* patcher la fonction de vérification elle-même (NOP du check ou saut conditionnel forcé)
* hooker la fonction **crc32** pour retourner toujours la même valeur
* suspendre ou neutraliser le thread de surveillance
* recalculer une nouvelle somme de référence après modification légitime
* debugger le processus et modifier la mémoire avant la vérification
* hooker **ExitProcess**

En pratique, l’objectif n’est pas d’empêcher totalement la modification, mais d’augmenter suffisamment le coût et la complexité de l’analyse pour décourager les attaques automatisées ou rapides.

C’est pour cette raison que les protections modernes ne reposent jamais sur un seul checksum isolé comme celui-ci.

##### Idées d’amélioration

Pour aller plus loin :
* surveiller uniquement .text
* utiliser plusieurs checksums
* lancer plusieurs threads
* vérifier à intervalles aléatoires
* conserver certaines zones sensibles chiffrées en mémoire et ne les déchiffrer qu’au runtime (uniquement lors de leur utilisation)
* combiner avec anti-debug

Mais la base reste toujours la même :
> Détecter qu’un tiers a modifié ce qui devait rester intact.

## Conclusion {#conclusion}

Dans ce projet, nous avons construit pas à pas les fondations d’un chargeur PE minimaliste, en reproduisant manuellement une grande partie du comportement du loader de Windows.

Même si certaines étapes comme les relocations complètes ou des mécanismes avancés de robustesse n’ont pas été implémentées ici, l’architecture générale d’un manual mapper fonctionnel est désormais en place.

Les techniques présentées ici constituent les bases du fonctionnement interne des loaders Windows. Elles sont reprises et étendues dans des loaders plus avancés, ainsi que dans des outils d’analyse et de reverse engineering utilisés en sécurité informatique.

Comprendre ces mécanismes permet donc à la fois de mieux appréhender le fonctionnement interne de Windows, mais aussi d’analyser et de détecter des comportements avancés dans des contextes de sécurité.

Le code complet du projet est disponible ici :
https://github.com/n0lanndev/pe-loader-toolkit

nolanndev

## ⚠️ Avertissement Légal (Disclaimer) {#disclaimer}

Ce cours est partagé à des fins strictement éducatives et dans un but de recherche en cybersécurité. Les techniques présentées (packing, chiffrement, manipulation de binaires) servent à comprendre le fonctionnement interne des systèmes Windows et des mécanismes de défense.
* **Usage responsable** : Ne testez jamais ces concepts sur un ordinateur ou un réseau qui ne vous appartient pas.
* **Responsabilité** : L'auteur décline toute responsabilité en cas de mauvaise utilisation de ces informations ou de dommages causés par une utilisation en dehors d'un cadre légal et éthique.
* **Éthique** : Le savoir est une arme ; utilisez-la pour construire des systèmes plus sûrs, pas pour nuire.