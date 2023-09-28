"""
    Bloodhound importer in python.
    Queries are borrowed from the BloodhoundAD project.
"""

import codecs
import json
import logging
import queue
import threading
import time
from dataclasses import dataclass
from os.path import basename
from tempfile import NamedTemporaryFile
from zipfile import ZipFile

import ijson
import neo4j

from bloodhound_import import database

running = True
q = queue.Queue()
total = 0
count = 0


@dataclass
class Query:
    query: str
    properties: dict


SYNC_COUNT = 100


def check_object(tx: neo4j.Transaction, source_label: str, type: str = "objectid", **kwargs) -> bool:
    query = 'UNWIND $props AS prop MATCH (n:{1} {{{0}: prop.source}}) RETURN n.{0} as {0}'
    query = query.format(type, source_label)
    result = [r for r in tx.run(query, **kwargs)]
    return len(result) > 0


def build_add_edge_query(source_label: str, target_label: str, edge_type: str, edge_props: str,
                         type: str = "objectid") -> str:
    """Build a standard edge insert query based on the given params"""
    insert_query = 'UNWIND $props AS prop MERGE (n:Base {{{0}: prop.source}}) ON MATCH SET n:{1} ON CREATE SET n:{1} MERGE (m:Base {{objectid: prop.target}}) ON MATCH SET m:{2} ON CREATE SET m:{2} MERGE (n)-[r:{3} {4}]->(m)'
    return insert_query.format(type, source_label, target_label, edge_type, edge_props)


def check_add_edge(tx: neo4j.Transaction, source_label: str, target_label: str, edge_type: str, edge_props: str,
                   type: str = "objectid", **kwargs) -> list:
    # source = kwargs.get('props', {}).get('source', None)
    # target = kwargs.get('props', {}).get('target', None)
    #
    # if source is None:
    #     raise Exception("Source is None")
    #
    # if target is None:
    #     raise Exception("Target is None")
    #
    # query = 'UNWIND $props AS prop MATCH (n:{1} {{{0}: prop.source}}) MATCH (m:{2} {{objectid: prop.target}}) MATCH (n)-[r:{3} {4}]->(m) RETURN n.{0} as source'
    # query = query.format(type, source_label, target_label, edge_type, edge_props)
    #
    # result = [
    #     r for r in tx.run(query, **kwargs)
    #     if r['source'] == source
    # ]
    #
    # if len(result) > 0:
    #     return []

    return [
        dict(
            query=build_add_edge_query(source_label, target_label, edge_type, edge_props, type),
            data=kwargs
        )
    ]


def process_ace_list(ace_list: list, objectid: str, objecttype: str, tx: neo4j.Transaction) -> list:
    for entry in ace_list:
        principal = entry['PrincipalSID']
        principaltype = entry['PrincipalType']
        right = entry['RightName']

        if objectid == principal:
            continue

        props = dict(
            source=principal,
            target=objectid,
            isinherited=entry['IsInherited'],
        )

        yield from check_add_edge(tx,
                                  principaltype, objecttype, right, '{isacl: true, isinherited: prop.isinherited}',
                                  props=props
                                  )


def process_spntarget_list(spntarget_list: list, objectid: str, tx: neo4j.Transaction) -> None:
    for entry in spntarget_list:
        props = dict(
            source=objectid,
            target=entry['ComputerSID'],
            port=entry['Port'],
        )
        yield from check_add_edge(tx,
                                  'User', 'Computer', 'WriteSPN', '{isacl: false, port: prop.port}',
                                  props=props
                                  )


def add_constraints(tx: neo4j.Transaction):
    """Adds bloodhound contraints to neo4j

    Arguments:
        tx {neo4j.Transaction} -- Neo4j transaction.
    """
    tx.run('CREATE CONSTRAINT base_objectid_unique ON (b:Base) ASSERT b.objectid IS UNIQUE')
    tx.run('CREATE CONSTRAINT computer_objectid_unique ON (c:Computer) ASSERT c.objectid IS UNIQUE')
    tx.run('CREATE CONSTRAINT domain_objectid_unique ON (d:Domain) ASSERT d.objectid IS UNIQUE')
    tx.run('CREATE CONSTRAINT group_objectid_unique ON (g:Group) ASSERT g.objectid IS UNIQUE')
    tx.run('CREATE CONSTRAINT user_objectid_unique ON (u:User) ASSERT u.objectid IS UNIQUE')
    tx.run("CREATE CONSTRAINT ON (c:User) ASSERT c.name IS UNIQUE")
    tx.run("CREATE CONSTRAINT ON (c:Computer) ASSERT c.name IS UNIQUE")
    tx.run("CREATE CONSTRAINT ON (c:Group) ASSERT c.name IS UNIQUE")
    tx.run("CREATE CONSTRAINT ON (c:Domain) ASSERT c.name IS UNIQUE")
    tx.run("CREATE CONSTRAINT ON (c:OU) ASSERT c.guid IS UNIQUE")
    tx.run("CREATE CONSTRAINT ON (c:GPO) ASSERT c.name IS UNIQUE")


def parse_ou(tx: neo4j.Transaction, ou: dict):
    """Parses a single ou.

    Arguments:
        tx {neo4j.Transaction} -- Neo4j session
        ou {dict} -- Single ou object.
    """
    trans = []
    identifier = ou['ObjectIdentifier'].upper()
    property_query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) SET n:OU SET n += prop.map'
    props = {'map': ou['Properties'], 'source': identifier}
    # if not check_object(tx, 'OU', props=props):
    trans += [
        dict(
            query=property_query,
            data=dict(
                props=props
            )
        )
    ]

    if 'Aces' in ou and ou['Aces'] is not None:
        trans += [t for t in process_ace_list(ou['Aces'], identifier, "OU", tx)]

    if 'ChildObjects' in ou and ou['ChildObjects']:
        targets = ou['ChildObjects']
        for target in targets:
            trans += check_add_edge('OU', target['ObjectType'], 'Contains', '{isacl: false}',
                                    props=dict(source=identifier, target=target['ObjectIdentifier']))

    if 'Links' in ou and ou['Links']:
        for gpo in ou['Links']:
            trans += check_add_edge(tx,
                                    'GPO', 'OU', 'GpLink', '{isacl: false, enforced: prop.enforced}',
                                    props=dict(source=identifier, target=gpo['GUID'].upper(),
                                               enforced=gpo['IsEnforced'])
                                    )

    options = [
        ('LocalAdmins', 'AdminTo'),
        ('PSRemoteUsers', 'CanPSRemote'),
        ('DcomUsers', 'ExecuteDCOM'),
        ('RemoteDesktopUsers', 'CanRDP'),
    ]

    if 'GPOChanges' in ou and ou['GPOChanges']:
        gpo_changes = ou['GPOChanges']
        affected_computers = gpo_changes['AffectedComputers']
        for option, edge_name in options:
            if option in gpo_changes and gpo_changes[option]:
                targets = gpo_changes[option]
                for target in targets:
                    for computer in affected_computers:
                        trans += check_add_edge(tx,
                                                target['ObjectType'], 'Computer', edge_name,
                                                '{isacl: false, fromgpo: true}',
                                                props=dict(source=computer['ObjectIdentifier'], target=target['ObjectIdentifier'])
                                                )
    return trans


def parse_gpo(tx: neo4j.Transaction, gpo: dict):
    """Parses a single GPO.

    Arguments:
        tx {neo4j.Transaction} -- Neo4j transaction
        gpo {dict} -- Single gpo object.
    """
    trans = []
    identifier = gpo['ObjectIdentifier']

    query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) SET n:GPO SET n += prop.map'
    props = {'map': gpo['Properties'], 'source': identifier}
    # tx.run(query, props=props)

    # if not check_object(tx, 'GPO', props=props):
    trans += [
        dict(
            query=query,
            data=dict(
                props=props
            )
        )
    ]

    if "Aces" in gpo and gpo["Aces"] is not None:
        trans += [t for t in process_ace_list(gpo['Aces'], identifier, "GPO", tx)]
    return trans


def parse_computer(tx: neo4j.Transaction, computer: dict):
    """Parse a computer object.

    Arguments:
        session {neo4j.Transaction} -- Neo4j transaction
        computer {dict} -- Single computer object.
    """
    trans = []
    identifier = computer['ObjectIdentifier']

    property_query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) SET n:Computer SET n += prop.map'
    props = {'map': computer['Properties'], 'source': identifier}

    # if not check_object(tx, 'Computer', props=props):
    trans += [
        dict(
            query=property_query,
            data=dict(
                props=props
            )
        )
    ]

    if 'PrimaryGroupSid' in computer and computer['PrimaryGroupSid']:
        trans += check_add_edge(tx,
                                'Computer', 'Group', 'MemberOf', '{isacl:false}',
                                props=dict(source=identifier, target=computer['PrimaryGroupSid'])
                                )

    if 'AllowedToDelegate' in computer and computer['AllowedToDelegate']:
        for entry in computer['AllowedToDelegate']:
            trans += check_add_edge(tx,
                                    'Computer', 'Group', 'MemberOf', '{isacl:false}',
                                    props=dict(source=identifier, target=entry)
                                    )

    # (Property name, Edge name, Use "Results" format)
    options = [
        ('LocalAdmins', 'AdminTo', True),
        ('RemoteDesktopUsers', 'CanRDP', True),
        ('DcomUsers', 'ExecuteDCOM', True),
        ('PSRemoteUsers', 'CanPSRemote', True),
        ('AllowedToAct', 'AllowedToAct', False),
        ('AllowedToDelegate', 'AllowedToDelegate', False),
    ]

    for option, edge_name, use_results in options:
        if option in computer:
            targets = computer[option]['Results'] if use_results else computer[option]
            for target in targets:
                # query = build_add_edge_query(target['ObjectType'], 'Computer', edge_name,
                #                              '{isacl:false, fromgpo: false}')
                # tx.run(query, props=dict(source=target['ObjectIdentifier'], target=identifier))
                if isinstance(target, str):
                    trans += check_add_edge(tx,
                                            'Base', 'Computer', edge_name, '{isacl:false, fromgpo: false}', "name",
                                            props=dict(source=target, target=identifier)
                                            )

                else:
                    trans += check_add_edge(tx,
                                        target['ObjectType'], 'Computer', edge_name, '{isacl:false, fromgpo: false}',
                                        props=dict(source=target['ObjectIdentifier'], target=identifier)
                                        )
    # (Session type, source)
    session_types = [
        ('Sessions', 'netsessionenum'),
        ('PrivilegedSessions', 'netwkstauserenum'),
        ('RegistrySessions', 'registry'),
    ]

    for session_type, source in session_types:
        if session_type in computer and computer[session_type]['Results']:
            for entry in computer[session_type]['Results']:
                # if 'UserId' in entry:
                trans += check_add_edge(tx,
                                        'Computer', 'User', 'HasSession', '{isacl:false, source:"%s"}' % source,
                                        props=dict(source=entry['UserSID'], target=identifier)
                                        )

    if 'Aces' in computer and computer['Aces'] is not None:
        trans += [t for t in process_ace_list(computer['Aces'], identifier, "Computer", tx)]
    return trans


def parse_user(tx: neo4j.Transaction, user: dict):
    """Parse a user object.

    Arguments:
        tx {neo4j.Transaction} -- Neo4j session
        user {dict} -- Single user object from the bloodhound json.
    """
    trans = []

    identifier = user['ObjectIdentifier']
    property_query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) SET n:User SET n += prop.map'
    props = {'map': user['Properties'], 'source': identifier}
    # if not check_object(tx, 'User', props=props):
    trans += [
        dict(
            query=property_query,
            data=dict(
                props=props
            )
        )
    ]

    if 'PrimaryGroupSid' in user and user['PrimaryGroupSid']:
        trans += check_add_edge(tx,
                                'User', 'Group', 'MemberOf', '{isacl: false}',
                                props=dict(source=identifier, target=user['PrimaryGroupSid'])
                                )

    if 'AllowedToDelegate' in user and user['AllowedToDelegate']:
        for entry in user['AllowedToDelegate']:
            trans += check_add_edge(tx,
                                    'User', 'Computer', 'AllowedToDelegate', '{isacl: false}',
                                    props=dict(source=identifier, target=entry['ObjectIdentifier'])
                                    )

    # TODO add HasSIDHistory objects

    if 'Aces' in user and user['Aces'] is not None:
        trans += [t for t in process_ace_list(user['Aces'], identifier, "User", tx)]

    if 'SPNTargets' in user and user['SPNTargets'] is not None:
        trans += [t for t in process_spntarget_list(user['SPNTargets'], identifier, tx)]

    return trans


def parse_group(tx: neo4j.Transaction, group: dict):
    """Parse a group object.

    Arguments:
        tx {neo4j.Transaction} -- Neo4j Transaction
        group {dict} -- Single group object from the bloodhound json.
    """
    trans = []
    properties = group['Properties']
    identifier = group['ObjectIdentifier']
    members = group['Members'] if 'Members' in group else []

    property_query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) SET n:Group SET n += prop.map'
    props = {'map': properties, 'source': identifier}
    trans += [
        dict(
            query=property_query,
            data=dict(
                props=props
            )
        )
    ]

    if 'Aces' in group and group['Aces'] is not None:
        trans += [t for t in process_ace_list(group['Aces'], identifier, "Group", tx)]

    for member in members:
        trans += check_add_edge(tx,
                                member['ObjectType'], 'Group', 'MemberOf', '{isacl: false}',
                                props=dict(source=member['ObjectIdentifier'], target=identifier)
                                )

    return trans


def parse_domain(tx: neo4j.Transaction, domain: dict):
    """Parse a domain object.

    Arguments:
        tx {neo4j.Transaction} -- Neo4j Transaction
        domain {dict} -- Single domain object from the bloodhound json.
    """
    trans = []

    identifier = domain['ObjectIdentifier']
    property_query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) SET n:Domain SET n += prop.map'
    props = {'map': domain['Properties'], 'source': identifier}
    # if not check_object(tx, 'Domain', props=props):
    trans += [
        dict(
            query=property_query,
            data=dict(
                props=props
            )
        )
    ]

    if 'Aces' in domain and domain['Aces'] is not None:
        trans += [t for t in process_ace_list(domain['Aces'], identifier, "Domain", tx)]

    trust_map = {0: 'ParentChild', 1: 'CrossLink', 2: 'Forest', 3: 'External', 4: 'Unknown'}
    if 'Trusts' in domain and domain['Trusts'] is not None:
        for trust in domain['Trusts']:
            trust_type = trust['TrustType']
            direction = trust['TrustDirection']
            props = {}
            if direction in [1, 3]:
                props = dict(
                    source=identifier,
                    target=trust['TargetDomainSid'],
                    trusttype=trust_map[trust_type],
                    transitive=trust['IsTransitive'],
                    sidfiltering=trust['SidFilteringEnabled'],
                )
            elif direction in [2, 4]:
                props = dict(
                    target=identifier,
                    source=trust['TargetDomainSid'],
                    trusttype=trust_map[trust_type],
                    transitive=trust['IsTransitive'],
                    sidfiltering=trust['SidFilteringEnabled'],
                )
            else:
                logging.error("Could not determine direction of trust... direction: %s", direction)
                continue
            trans += check_add_edge(tx,
                                    'Domain', 'Domain', 'TrustedBy',
                                    '{sidfiltering: prop.sidfiltering, trusttype: prop.trusttype, transitive: prop.transitive, isacl: false}',
                                    props=props
                                    )

    if 'ChildObjects' in domain and domain['ChildObjects']:
        targets = domain['ChildObjects']
        for target in targets:
            props = dict(source=identifier, target=target['ObjectIdentifier'])
            trans += check_add_edge(tx,
                                    'Domain', target['ObjectType'], 'Contains', '{isacl: false}',
                                    props=props
                                    )

    if 'Links' in domain and domain['Links']:
        for gpo in domain['Links']:
            props = dict(source=identifier, target=gpo['GUID'].upper(), enforced=gpo['IsEnforced'])
            trans += check_add_edge(tx,
                                    'GPO', 'OU', 'GpLink', '{isacl: false, enforced: prop.enforced}',
                                    props=props
                                    )

    options = [
        ('LocalAdmins', 'AdminTo'),
        ('PSRemoteUsers', 'CanPSRemote'),
        ('DcomUsers', 'ExecuteDCOM'),
        ('RemoteDesktopUsers', 'CanRDP'),
    ]

    if 'GPOChanges' in domain and domain['GPOChanges']:
        gpo_changes = domain['GPOChanges']
        affected_computers = gpo_changes['AffectedComputers']
        for option, edge_name in options:
            if option in gpo_changes and gpo_changes[option]:
                targets = gpo_changes[option]
                for target in targets:
                    for computer in affected_computers:
                        props = dict(source=computer['ObjectIdentifier'], target=target['ObjectIdentifier'])
                        trans += check_add_edge(tx,
                                                target['ObjectType'], 'Computer', edge_name,
                                                '{isacl: false, fromgpo: true}',
                                                props=props
                                                )

    return trans


def parse_container(tx: neo4j.Transaction, container: dict):
    """Parse a Container object.

    Arguments:
        tx {neo4j.Transaction} -- Neo4j session
        container {dict} -- Single container object from the bloodhound json.
    """
    trans = []
    identifier = container['ObjectIdentifier']
    property_query = 'UNWIND $props AS prop MERGE (n:Base {objectid: prop.source}) SET n:Container SET n += prop.map'
    props = {'map': container['Properties'], 'source': identifier}
    # if not check_object(tx, 'Container', props=props):
    trans += [
        dict(
            query=property_query,
            data=dict(
                props=props
            )
        )
    ]

    if 'Aces' in container and container['Aces'] is not None:
        trans += [t for t in process_ace_list(container['Aces'], identifier, "Container", tx)]

    if 'ChildObjects' in container and container['ChildObjects']:
        targets = container['ChildObjects']
        for target in targets:
            props = dict(source=identifier, target=target['ObjectIdentifier'])
            trans += check_add_edge(tx,
                                    'Container', target['ObjectType'], 'Contains', '{isacl: false}',
                                    props=props
                                    )
    return trans


def parse_zipfile(filename: str, driver: neo4j.Driver):
    """Parse a bloodhound zip file.

    Arguments:
        filename {str} -- ZIP filename to parse.
        driver {neo4j.GraphDatabase} -- driver to connect to neo4j.
    """
    with ZipFile(filename) as zip_file:
        for file in zip_file.namelist():
            if not file.endswith('.json'):
                logging.info("File does not appear to be JSON, skipping: %s", file)
                continue

            with NamedTemporaryFile(suffix=basename(file)) as temp:
                temp.write(zip_file.read(file))
                temp.flush()
                parse_file(temp.name, driver)


def executer(tx: neo4j.Transaction, transactions: list):
    for t in transactions:
        data = t['data']
        if not isinstance(data, dict):
            logging.error("Invalid data: %s", data)
            continue
        tx.run(t['query'], **data)


def worker(index, parse_function, **kwargs):
    global running, count
    icount = 0
    driver = database.init_sync_driver(**kwargs)
    while running and icount < 100:
        entry = q.get()
        try:
            do_task(entry, parse_function, driver)

        except neo4j.exceptions.TransientError as e:
            # Deadlock, try to reopen a new connection
            driver.close()
            time.sleep(0.500)
            driver = database.init_sync_driver(**kwargs)

            try:
                do_task(entry, parse_function, driver)
            except neo4j.exceptions.TransientError as e:
                logging.error("Could not resolve the error: %s", e)

        except KeyboardInterrupt as e:
            running = False
            raise e
        finally:
            q.task_done()
            icount += 1
            count += 1

    driver.close()

    # Create a new thread
    # Cicle the thread every 100 requests, to release the driver, memory e etc...
    if running:
        kwargs.update(dict(index=index, parse_function=parse_function))
        t = threading.Thread(target=worker, kwargs=kwargs)
        t.daemon = True
        t.start()

    # Nedded for exit thread
    return


def do_task(entry, parse_function, driver: neo4j.GraphDatabase):
    global total
    for retry in range(5):

        try:
            with driver.session() as session:
                transactions = session.write_transaction(parse_function, entry)

            if isinstance(transactions, list) and len(transactions) > 0:
                with driver.session() as session:
                    session.write_transaction(executer, transactions)

            break
        except KeyboardInterrupt as e:
            raise e
        except neo4j.exceptions.ConstraintError as e:
            print(e)
            return
        except Exception as e:
            time.sleep(0.500)
            if isinstance(e, neo4j.exceptions.TransientError):

                if retry > 3:
                    logging.error("neo4j.exceptions.TransientError: %s", e)
                    raise e

                # Deadlock, wait more time
                time.sleep(0.500)

            if retry > 3:
                logging.error(f"Could not process the registry: {parse_function} {json.dumps(entry)}")
                logging.error(e)
                logging.error(e.__class__)

                return


def parse_file(filename: str, driver: neo4j.AsyncDriver, props: dict = None, kwargs: dict = None):
    """Parse a bloodhound file.

    Arguments:
        filename {str} -- JSON filename to parse.
        driver {neo4j.GraphDatabase} -- driver to connect to neo4j.
    """
    logging.info("Parsing bloodhound file: %s", filename)

    if filename.endswith('.zip'):
        logging.info("File appears to be a zip file, importing all containing JSON files..")
        parse_zipfile(filename, driver)
        return

    with codecs.open(filename, 'r', encoding='utf-8-sig') as f:
        meta = ijson.items(f, 'meta')
        for o in meta:
            obj_type = o['type']
            total = o['count']

    parsing_map = {
        'computers': parse_computer,
        'containers': parse_container,
        'users': parse_user,
        'groups': parse_group,
        'domains': parse_domain,
        'gpos': parse_gpo,
        'ous': parse_ou
    }

    parse_function = None
    try:
        parse_function = parsing_map[obj_type]
    except KeyError:
        logging.error("Parsing function for object type: %s was not found.", obj_type)
        return
    threads = int(total / 500)

    if threads > 5:
        threads = 5

    if threads <= 0:
        threads = 1

    logging.info("Starting %s threads", threads)

    # Status Thread
    t = threading.Thread()
    t.daemon = True
    t.start()

    # worker threads
    for i in range(threads):
        kwargs.update(dict(index=i, parse_function=parse_function))
        t = threading.Thread(target=worker, kwargs=kwargs)
        t.daemon = True
        t.start()

    with q.mutex:
        q.queue.clear()

    logging.getLogger().setLevel(logging.ERROR)
    running = True

    with open(filename, 'r', encoding="utf-8-sig") as f:
        objs = ijson.items(f, 'data.item')
        try:
            for entry in objs:
                if props and 'Properties' in entry:
                    entry['Properties'].update(props)
                q.put(entry)
                # do_task(entry, parse_function, driver)

        except KeyboardInterrupt as e:
            running = False

    while running:
        try:
            l = len(q.queue)
            if l > 0:
                # print((" " * 80) + str(l), end='\r', flush=True)
                time.sleep(0.3 if l < 1000 else 5)
            else:
                running = False
        except KeyboardInterrupt as e:
            logging.error("interrupted by user")
            with q.mutex:
                q.queue.clear()

            running = False

    logging.getLogger().setLevel(logging.INFO)

    logging.info("Parsed %d out of %d records in %s.", count, total, filename)

    logging.info("Completed file: %s", filename)
    # ten_percent = total // 10 if total > 10 else 1
    # count = 0
    # f = codecs.open(filename, 'r', encoding='utf-8-sig')
    # objs = ijson.items(f, 'data.item')
    # with driver.session() as session:
    #     for entry in objs:
    #         # Add additional properties to entity if provided
    #         if props and 'Properties' in entry:
    #             entry['Properties'].update(props)
    #         try:
    #             session.write_transaction(parse_function, entry)
    #             count = count + 1
    #         except neo4j.exceptions.ConstraintError as e:
    #             print(e)
    #         if count % ten_percent == 0:
    #             logging.info("Parsed %d out of %d records in %s.", count, total, filename)
    #
    # f.close()
    # logging.info("Completed file: %s", filename)
